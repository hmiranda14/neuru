<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Switch engine. Classifies monitored nodes as switches and serves the
// Switch Control Center hub + the SNMP Switches page. Universal: auto-detects
// switch-ness from the device model/OS (MikroTik SwOS/CSS/CRS, Cisco Catalyst/
// Nexus, HP ProCurve, Aruba, Juniper EX/QFX, TP-Link Easy-Smart, generic SGxxx…)
// and lets the operator override the role per node. Port data comes from the
// existing nm_interfaces + nm_port_stats — no parallel inventory.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_sw_ensure')) {

    function nm_sw_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        // per-node role override ('' = auto). Guarded ALTER (mysqli exception mode).
        try {
            $h = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_nodes' AND COLUMN_NAME='device_role'");
            if ($h && $h->num_rows === 0) { try { $conn->query("ALTER TABLE nm_nodes ADD COLUMN device_role VARCHAR(16) DEFAULT NULL"); } catch (\Throwable $e) {} }
        } catch (\Throwable $e) {}
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','switches',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='switches')");
    }

    // Is this device a switch? Manual role wins; else infer from model/OS signatures.
    function nm_sw_is_switch(array $n): bool {
        $role = strtolower(trim((string)($n['device_role'] ?? '')));
        if ($role === 'switch') return true;
        if ($role !== '' && $role !== 'auto') return false;    // explicitly something else
        $hay = strtolower(($n['hw_model'] ?? '').' '.($n['os_icon'] ?? '').' '.($n['display_name'] ?? '').' '.($n['model'] ?? ''));
        // switch signatures across vendors
        $sw = ['swos','css10','crs1','crs2','crs3','crs5','catalyst',' nexus','procurve','aruba','powerconnect',
               'easy smart','easy-smart','easysmart',' ex2',' ex3',' ex4','qfx',' sg1',' sg2',' sg3',' sg5',
               'gs108','gs308','gs724','tl-sg','tl-sf','switch'];
        foreach ($sw as $s) if (strpos($hay, $s) !== false) return true;
        return false;
    }
    // Resolve a node's role label (for display / the role selector).
    function nm_sw_role(array $n): string {
        $role = strtolower(trim((string)($n['device_role'] ?? '')));
        if ($role !== '' && $role !== 'auto') return $role;
        if (nm_sw_is_switch($n)) return 'switch';
        require_once __DIR__.'/nm_nodemeta.php';
        return function_exists('nm_node_kind') ? nm_node_kind($n) : 'snmp';
    }

    function nm_sw_set_role($conn, int $node_id, string $role): array {
        nm_sw_ensure($conn);
        $role = in_array($role, ['auto','switch','router','server','ap','firewall','other'], true) ? $role : 'auto';
        $val = $role === 'auto' ? null : $role;
        $st = $conn->prepare("UPDATE nm_nodes SET device_role=? WHERE id=?");
        $st->bind_param('si', $val, $node_id); $st->execute(); $st->close();
        if (function_exists('nm_audit')) { try { nm_audit($conn,'switch.role',['target_type'=>'node','target_id'=>$node_id,'details'=>['role'=>$role]]); } catch (\Throwable $e) {} }
        return ['ok'=>true];
    }

    // Node columns needed for classification (guards optional 'model').
    function nm_sw_node_cols($conn): string {
        static $has = null;
        if ($has === null) { $has = false; try { $r=$conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_nodes' AND COLUMN_NAME='model'"); $has = $r && $r->num_rows>0; } catch (\Throwable $e) {} }
        return "id,display_name,ip_address,os_icon,hw_model,monitor_type,device_role".($has?",model":"");
    }

    // SNMP (and generic) switches: nodes classified as a switch that are NOT ping-only
    // unmanaged boxes (those live in l2switch.php) and NOT Cisco (cisco_switch.php).
    function nm_sw_snmp_switches($conn): array {
        nm_sw_ensure($conn);
        $cols = nm_sw_node_cols($conn);
        $out = []; $r = $conn->query("SELECT $cols FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>'' ORDER BY display_name");
        while ($r && ($x = $r->fetch_assoc())) {
            if (!nm_sw_is_switch($x)) continue;
            $os = strtolower((string)$x['os_icon']);
            if (strpos($os,'cisco') !== false) continue;                 // Cisco → its own page
            if (($x['monitor_type'] ?? '') === 'ping') continue;          // unmanaged/ping-only → l2switch
            $out[] = $x;
        }
        return $out;
    }
    // Candidate nodes the operator might want to tag as a switch (for the "not detected?" helper).
    function nm_sw_candidates($conn): array {
        nm_sw_ensure($conn);
        $cols = nm_sw_node_cols($conn);
        $out=[]; $r=$conn->query("SELECT $cols FROM nm_nodes WHERE monitor_type='snmp' AND ip_address<>'' ORDER BY display_name");
        while ($r && ($x=$r->fetch_assoc())) { if (!nm_sw_is_switch($x)) $out[]=['id'=>(int)$x['id'],'name'=>$x['display_name'],'ip'=>$x['ip_address'],'model'=>$x['hw_model']]; }
        return $out;
    }

    // Port faceplate for one switch: each interface + its latest oper status / speed / util.
    function nm_sw_ports($conn, int $node_id): array {
        if (!$conn->query("SHOW TABLES LIKE 'nm_interfaces'")->num_rows) return [];
        $ports = [];
        $r = $conn->query("SELECT id,if_name,if_alias,if_index,sort_order FROM nm_interfaces WHERE node_id=".(int)$node_id." AND COALESCE(is_dummy,0)=0 ORDER BY sort_order, if_index, id");
        while ($r && ($x = $r->fetch_assoc())) $ports[(int)$x['id']] = [
            'port_id'=>(int)$x['id'],'name'=>$x['if_name'] ?: ('port '.$x['if_index']),'alias'=>$x['if_alias'],
            'if_index'=>(int)$x['if_index'],'status'=>null,'speed'=>null,'util'=>0.0,'in_rate'=>0,'out_rate'=>0];
        if (!$ports) return [];
        // latest sample per port
        if ($conn->query("SHOW TABLES LIKE 'nm_port_stats'")->num_rows) {
            $ids = implode(',', array_map('intval', array_keys($ports)));
            $q = $conn->query("SELECT p.port_id,p.oper_status,p.if_speed,p.in_util,p.out_util,p.in_rate,p.out_rate
                FROM nm_port_stats p INNER JOIN (SELECT port_id,MAX(recorded_at) mx FROM nm_port_stats WHERE node_id=".(int)$node_id." AND port_id IN ($ids) GROUP BY port_id) l
                ON p.port_id=l.port_id AND p.recorded_at=l.mx WHERE p.node_id=".(int)$node_id);
            while ($q && ($x = $q->fetch_assoc())) {
                $pid=(int)$x['port_id']; if (!isset($ports[$pid])) continue;
                $ports[$pid]['status'] = strtolower((string)$x['oper_status']);
                $ports[$pid]['speed']  = (int)$x['if_speed'];
                $ports[$pid]['util']   = max((float)$x['in_util'],(float)$x['out_util']);
                $ports[$pid]['in_rate']= (float)$x['in_rate']; $ports[$pid]['out_rate']=(float)$x['out_rate'];
            }
        }
        return array_values($ports);
    }

    // Best-effort device vitals for the switch header (uptime + any CPU/Mem/Temp the device
    // exposes — SwOS has none, Cisco/other SNMP switches may). Reads the canonical nm_device_stats.
    function nm_sw_vitals($conn, int $node_id): array {
        $v = ['uptime'=>null,'cpu'=>null,'mem'=>null,'temp'=>null];
        if (!$conn->query("SHOW TABLES LIKE 'nm_device_stats'")->num_rows) return $v;
        $latest = function(string $type, ?string $key=null) use ($conn,$node_id) {
            $w = "node_id=".(int)$node_id." AND metric_type='".$conn->real_escape_string($type)."'".($key?" AND metric_key='".$conn->real_escape_string($key)."'":"");
            $r = $conn->query("SELECT value FROM nm_device_stats WHERE $w ORDER BY recorded_at DESC LIMIT 1");
            return ($r && ($x=$r->fetch_row())) ? (float)$x[0] : null;
        };
        $v['uptime'] = $latest('uptime','seconds');
        $v['cpu']    = $latest('cpu','avg');
        $v['mem']    = $latest('memory');
        $v['temp']   = $latest('temperature');
        return $v;
    }

    // Total live throughput across a switch's ports (bytes/sec in+out) for the header.
    function nm_sw_throughput(array $ports): array {
        $in=0.0; $out=0.0;
        foreach ($ports as $p) { $in += (float)($p['in_rate']??0); $out += (float)($p['out_rate']??0); }
        return ['in'=>$in,'out'=>$out];
    }

    // Counts for the Switch Control Center tiles (best-effort per feature).
    function nm_sw_counts($conn): array {
        nm_sw_ensure($conn);
        $snmp = count(nm_sw_snmp_switches($conn));
        // Cisco switches
        $cisco = 0;
        try { $cols=nm_sw_node_cols($conn); $r=$conn->query("SELECT $cols FROM nm_nodes WHERE ip_address<>''");
            while ($r && ($x=$r->fetch_assoc())) { $os=strtolower((string)$x['os_icon']); if (strpos($os,'cisco')!==false && nm_sw_is_switch($x)) $cisco++; }
        } catch (\Throwable $e) {}
        // Unmanaged (TP-Link Easy-Smart) — count from its table if present, else ping-only switch-ish nodes
        $unmanaged = 0;
        try { if ($conn->query("SHOW TABLES LIKE 'nm_tplink'")->num_rows) $unmanaged=(int)($conn->query("SELECT COUNT(*) FROM nm_tplink")->fetch_row()[0] ?? 0); } catch (\Throwable $e) {}
        if (!$unmanaged) { try { $cols=nm_sw_node_cols($conn); $r=$conn->query("SELECT $cols FROM nm_nodes WHERE monitor_type='ping' AND ip_address<>''");
            while ($r && ($x=$r->fetch_assoc())) if (nm_sw_is_switch($x)) $unmanaged++; } catch (\Throwable $e) {} }
        return ['snmp'=>$snmp,'cisco'=>$cisco,'unmanaged'=>$unmanaged];
    }
}
