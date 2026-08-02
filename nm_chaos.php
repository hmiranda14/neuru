<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Chaos / Blast-Radius engine. "What breaks if THIS node dies?"
//
// Builds the real dependency graph from BOTH topology sources NEURU already has:
//   · nm_links        — manual A↔Z connections (the mesh; gives redundancy)
//   · gateway_node_id — each node's upstream gateway (the tree)
// then simulates a node failure by removing it and re-running reachability from
// the CORE/egress roots. A node only counts as "lost" if it had NO surviving path
// (so redundant links protect it). Maps the fallout onto BUSINESS SERVICES (VoIP,
// DB, portal…) you define, and ranks the worst single points of failure (SPOFs).
//
// Page gate = permission key 'chaos'. Reuses the topology of [[netmon-incidents]].
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_chaos_simulate')) {

    function nm_chaos_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done=false; if($done) return; $done=true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_services (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(120) NOT NULL,
            criticality VARCHAR(8) NOT NULL DEFAULT 'high',
            description VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_service_deps (
            id INT AUTO_INCREMENT PRIMARY KEY,
            service_id INT NOT NULL,
            node_id INT NOT NULL,
            weight INT NOT NULL DEFAULT 1,
            is_critical TINYINT(1) NOT NULL DEFAULT 0,
            UNIQUE KEY uniq_sd (service_id, node_id),
            KEY idx_svc (service_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled)
            SELECT 'admin','chaos',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='chaos')");
    }
    function nm_chaos_setting($conn,$k,$d){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }

    // ── Build the undirected dependency graph ────────────────────────────────
    function nm_chaos_graph($conn): array {
        $adj=[]; $names=[]; $gw=[];
        $r=$conn->query("SELECT id,display_name,gateway_node_id FROM nm_nodes");
        while($r&&$x=$r->fetch_assoc()){ $id=(int)$x['id']; $names[$id]=$x['display_name']; $adj[$id]=$adj[$id]??[];
            $gw[$id]=$x['gateway_node_id']?(int)$x['gateway_node_id']:null; }
        // gateway edges (child ↔ parent)
        foreach($gw as $id=>$g){ if($g && isset($adj[$g])){ $adj[$id][$g]=1; $adj[$g][$id]=1; } }
        // manual link edges (A ↔ Z)
        $r=$conn->query("SELECT a_node_id,z_node_id FROM nm_links WHERE enabled=1");
        while($r&&$x=$r->fetch_assoc()){ $a=(int)$x['a_node_id']; $z=(int)$x['z_node_id'];
            if($a&&$z&&isset($adj[$a])&&isset($adj[$z])){ $adj[$a][$z]=1; $adj[$z][$a]=1; } }
        return ['adj'=>$adj,'names'=>$names,'gw'=>$gw];
    }

    // Core/egress roots: explicit set (setting) preferred; else gateway-less nodes.
    function nm_chaos_roots($conn,$G): array {
        $core = array_values(array_filter(array_map('intval', explode(',', (string)nm_chaos_setting($conn,'chaos_core_node_ids','')))));
        if($core) return array_values(array_intersect($core, array_keys($G['adj'])));
        $roots=[]; foreach($G['gw'] as $id=>$g){ if(!$g && isset($G['adj'][$id])) $roots[]=$id; }
        return $roots;
    }

    // BFS reachability from roots, optionally removing nodes.
    function nm_chaos_reach(array $adj, array $roots, array $exclude=[]): array {
        $ex=array_flip($exclude); $seen=[]; $q=[];
        foreach($roots as $r){ if(!isset($ex[$r]) && isset($adj[$r])){ $seen[$r]=1; $q[]=$r; } }
        while($q){ $n=array_shift($q); foreach(array_keys($adj[$n]??[]) as $m){ if(!isset($ex[$m]) && !isset($seen[$m])){ $seen[$m]=1; $q[]=$m; } } }
        return $seen;
    }

    // Map an affected-node set onto the defined business services.
    function nm_chaos_service_impact($conn, array $affected): array {
        $out=[]; $svcs=$conn->query("SELECT * FROM nm_services ORDER BY FIELD(criticality,'high','medium','low'), name");
        while($svcs&&$s=$svcs->fetch_assoc()){
            $sid=(int)$s['id'];
            $dr=$conn->query("SELECT d.node_id,d.weight,d.is_critical,n.display_name FROM nm_service_deps d LEFT JOIN nm_nodes n ON n.id=d.node_id WHERE d.service_id={$sid}");
            $tot=0;$aff=0;$crit=false;$affNodes=[];
            while($dr&&$d=$dr->fetch_assoc()){ $w=max(1,(int)$d['weight']); $tot+=$w;
                if(isset($affected[(int)$d['node_id']])){ $aff+=$w; $affNodes[]=$d['display_name']?:('node '.$d['node_id']); if($d['is_critical'])$crit=true; } }
            if($tot===0) continue;
            $pct=(int)round($aff/$tot*100);
            $status=($crit||$pct>=100)?'down':($pct>0?'degraded':'ok');
            $out[]=['id'=>$sid,'name'=>$s['name'],'criticality'=>$s['criticality'],'impact'=>$pct,'status'=>$status,'affected_nodes'=>$affNodes];
        }
        return $out;
    }

    // ── The what-if: fail one node, compute the cascade ──────────────────────
    function nm_chaos_simulate($conn, int $failId): array {
        nm_chaos_ensure($conn);
        $G=nm_chaos_graph($conn); $roots=nm_chaos_roots($conn,$G);
        $R0=nm_chaos_reach($G['adj'],$roots,[]);
        $R1=nm_chaos_reach($G['adj'],$roots,[$failId]);
        $blast=[]; foreach($R0 as $id=>$_){ if($id!==$failId && !isset($R1[$id])) $blast[]=$id; }
        $affected=array_flip($blast); $affected[$failId]=1;
        return [
            'fail'=>['id'=>$failId,'name'=>$G['names'][$failId]??('node '.$failId)],
            'fail_is_root'=>in_array($failId,$roots,true),
            'roots'=>array_map(fn($r)=>['id'=>$r,'name'=>$G['names'][$r]??('node '.$r)],$roots),
            'blast'=>array_map(fn($id)=>['id'=>$id,'name'=>$G['names'][$id]??('node '.$id)],$blast),
            'blast_count'=>count($blast),
            'reachable_before'=>count($R0),
            'services'=>nm_chaos_service_impact($conn,$affected),
            'graphed'=>count($R0)>0,
        ];
    }

    // ── Rank single points of failure (run the sim for every node) ───────────
    function nm_chaos_spofs($conn, int $limit=20): array {
        nm_chaos_ensure($conn);
        $G=nm_chaos_graph($conn); $roots=nm_chaos_roots($conn,$G);
        $R0=nm_chaos_reach($G['adj'],$roots,[]);
        $out=[];
        foreach(array_keys($G['adj']) as $id){
            if(!isset($R0[$id])) continue;                 // only nodes actually in the connected topology
            $R1=nm_chaos_reach($G['adj'],$roots,[$id]);
            $affected=[]; foreach($R0 as $nid=>$_){ if($nid!==$id && !isset($R1[$nid])) $affected[$nid]=1; }
            $blast=count($affected); $affected[$id]=1;
            $svc=nm_chaos_service_impact($conn,$affected);
            $svcDown=count(array_filter($svc,fn($s)=>$s['status']==='down'));
            $svcDeg =count(array_filter($svc,fn($s)=>$s['status']==='degraded'));
            if($blast>0 || $svcDown>0 || $svcDeg>0)
                $out[]=['id'=>$id,'name'=>$G['names'][$id]??('node '.$id),'blast'=>$blast,'svc_down'=>$svcDown,'svc_deg'=>$svcDeg,
                    'svc'=>array_values(array_filter($svc,fn($s)=>$s['status']!=='ok'))];
        }
        usort($out, fn($a,$b)=>[$b['svc_down'],$b['blast'],$b['svc_deg']] <=> [$a['svc_down'],$a['blast'],$a['svc_deg']]);
        return array_slice($out,0,$limit);
    }

    // ── Services CRUD ────────────────────────────────────────────────────────
    function nm_chaos_services($conn): array {
        nm_chaos_ensure($conn); $out=[];
        $r=$conn->query("SELECT s.*, (SELECT COUNT(*) FROM nm_service_deps d WHERE d.service_id=s.id) dep_count
                         FROM nm_services s ORDER BY FIELD(s.criticality,'high','medium','low'), s.name");
        while($r&&$x=$r->fetch_assoc()) $out[]=$x;
        return $out;
    }
    function nm_chaos_service_deps($conn,int $sid): array {
        $out=[]; $st=$conn->prepare("SELECT d.*, n.display_name FROM nm_service_deps d LEFT JOIN nm_nodes n ON n.id=d.node_id WHERE d.service_id=? ORDER BY d.is_critical DESC, n.display_name");
        $st->bind_param('i',$sid); $st->execute(); $r=$st->get_result(); while($x=$r->fetch_assoc()) $out[]=$x;
        return $out;
    }
    function nm_chaos_service_save($conn, array $d): int {
        nm_chaos_ensure($conn);
        $id=(int)($d['id']??0); $name=substr(trim((string)($d['name']??'')),0,120);
        $crit=in_array(($d['criticality']??''),['high','medium','low'],true)?$d['criticality']:'high';
        $desc=substr((string)($d['description']??''),0,255);
        if($name==='') return 0;
        if($id){ $st=$conn->prepare("UPDATE nm_services SET name=?,criticality=?,description=? WHERE id=?"); $st->bind_param('sssi',$name,$crit,$desc,$id); $st->execute(); }
        else { $st=$conn->prepare("INSERT INTO nm_services (name,criticality,description) VALUES (?,?,?)"); $st->bind_param('sss',$name,$crit,$desc); $st->execute(); $id=$conn->insert_id; }
        // deps: array of {node_id, is_critical, weight}
        if (isset($d['deps']) && is_array($d['deps'])) {
            $conn->query("DELETE FROM nm_service_deps WHERE service_id={$id}");
            $ins=$conn->prepare("INSERT IGNORE INTO nm_service_deps (service_id,node_id,weight,is_critical) VALUES (?,?,?,?)");
            foreach($d['deps'] as $dep){ $nid=(int)($dep['node_id']??0); if(!$nid)continue; $w=max(1,(int)($dep['weight']??1)); $cr=!empty($dep['is_critical'])?1:0;
                $ins->bind_param('iiii',$id,$nid,$w,$cr); $ins->execute(); }
        }
        return $id;
    }
    function nm_chaos_service_delete($conn,int $id){ $conn->query("DELETE FROM nm_service_deps WHERE service_id=".(int)$id); $conn->query("DELETE FROM nm_services WHERE id=".(int)$id); }
}
