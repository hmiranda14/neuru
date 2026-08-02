<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Widget SDK platform (FOUNDATION layer). Everything user-facing (the
// no-code builder, AI-generated widgets, sandboxed code widgets) stands on this:
//
//   1) DATA BROKER  — a curated, versioned catalog of READ-ONLY data sources.
//      Widgets DECLARE what they need; the host resolves it with the *user's own*
//      permissions and hands back JSON. Widgets never touch the DB, run SQL, hit
//      arbitrary URLs, or see the session/tokens. This is the stable public API.
//
//   2) MANIFEST     — a versioned `.neuruwidget` JSON document + a validator.
//
//   3) REGISTRY     — DB-backed install/list/remove of user & global widgets,
//      alongside the built-in ones in command.php.
//
// RBAC: the Command Center ('command') gates the endpoints; EACH data source adds
// its own permission check on top, so a widget can never escalate.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_widgets_ensure')) {
    require_once __DIR__ . '/nm_command.php';     // nm_cmd_* + nm_geomap_* resolvers
    require_once __DIR__ . '/nm_incidents.php';   // nm_inc_list
    require_once __DIR__ . '/access_control.php'; // checkAccess (per-source perm gate)

    if (!defined('NM_WIDGET_SDK')) define('NM_WIDGET_SDK', '1.0');

    function nm_widgets_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_widgets (
            row_id     INT AUTO_INCREMENT PRIMARY KEY,
            widget_id  VARCHAR(80)  NOT NULL,
            owner_uid  INT          NOT NULL,
            scope      VARCHAR(10)  NOT NULL DEFAULT 'user',   -- user | global
            name       VARCHAR(120) NOT NULL,
            manifest   LONGTEXT     NOT NULL,
            enabled    TINYINT(1)   NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_owner_widget (owner_uid, widget_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','command',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='command')");
    }

    // ── 1) DATA BROKER ─────────────────────────────────────────────────────────
    // The curated catalog. Each entry: the permission it requires, accepted params
    // (with caps), a one-line description, and the SHAPE of what it returns (so the
    // builder/AI know which fields a widget can map). `kind` = list (array) | object.
    function nm_ds_catalog(): array {
        return [
          'incidents.active' => ['perm'=>'incidents','kind'=>'list','desc'=>'Open + acknowledged incidents',
              'params'=>['limit'=>[1,200,50]], 'fields'=>['id','title','severity','status','root_entity','impact_count','opened_at']],
          'nodes.status' => ['perm'=>'net_mon','kind'=>'list','desc'=>'Monitored nodes with up/down state',
              'params'=>['limit'=>[1,500,200]], 'fields'=>['id','name','ip','status']],
          'netflow.top' => ['perm'=>'netflow','kind'=>'list','desc'=>'Top NetFlow talkers (Mb/s)',
              'params'=>['limit'=>[1,40,20],'mins'=>[1,120,10]], 'fields'=>['ip','mbps','flows']],
          'interfaces.top' => ['perm'=>'net_mon','kind'=>'list','desc'=>'Busiest interfaces by traffic',
              'params'=>['limit'=>[1,40,12]], 'fields'=>['node','iface','in_rate','out_rate','total']],
          'interfaces.series' => ['perm'=>'net_mon','kind'=>'list','desc'=>'Top interfaces in/out traffic over time (bps arrays — for line charts)',
              'params'=>['limit'=>[1,12,5],'mins'=>[5,1440,60]], 'fields'=>['node','iface','label','times','in','out','cur_in','cur_out']],
          'syslog.recent' => ['perm'=>'log_mon','kind'=>'list','desc'=>'Most recent syslog lines',
              'params'=>['limit'=>[1,80,25]], 'fields'=>['at','host','ip','sev','tag','msg']],
          'containers.list' => ['perm'=>'containers','kind'=>'list','desc'=>'Containers (name/state/host)',
              'params'=>[], 'fields'=>['name','state','host','image']],
          'smokeping.latest' => ['perm'=>'smokeping','kind'=>'list','desc'=>'Per-node latest RTT',
              'params'=>['limit'=>[1,30,12]], 'fields'=>['node_id','name','rtt','avg']],
          'pihole.top' => ['perm'=>'pihole','kind'=>'object','desc'=>'Pi-hole top domains/clients + totals',
              'params'=>[], 'fields'=>['queries','clients','total','blocked_pct']],
          'ping.node' => ['perm'=>'net_mon','kind'=>'object','desc'=>'Latest ping for one node',
              'params'=>['node'=>[1,9999999,0]], 'fields'=>['node_id','is_up','latency_ms','loss','at']],
          'nodes.down' => ['perm'=>'net_mon','kind'=>'list','desc'=>'Nodes currently down',
              'params'=>[], 'fields'=>['name','ip']],
          'netflow.apps' => ['perm'=>'netflow','kind'=>'list','desc'=>'Top applications by bandwidth',
              'params'=>['limit'=>[1,40,12],'mins'=>[1,120,10]], 'fields'=>['app','mbps','port','proto','flows']],
          'netflow.protocols' => ['perm'=>'netflow','kind'=>'list','desc'=>'Top protocols by bandwidth',
              'params'=>['limit'=>[1,20,8],'mins'=>[1,120,10]], 'fields'=>['proto','mbps','bytes']],
          'netflow.dst' => ['perm'=>'netflow','kind'=>'list','desc'=>'Top destination talkers',
              'params'=>['limit'=>[1,40,12],'mins'=>[1,120,10]], 'fields'=>['ip','mbps','flows']],
          'netflow.summary' => ['perm'=>'netflow','kind'=>'object','desc'=>'NetFlow totals (avg Mb/s, flows, talkers)',
              'params'=>['mins'=>[1,120,10]], 'fields'=>['avg_mbps','flows','talkers','packets']],
          'health.forecasts' => ['perm'=>'health','kind'=>'list','desc'=>'Predictive health — what will degrade & when',
              'params'=>['limit'=>[1,100,20]], 'fields'=>['node','metric','severity','eta_days','detail']],
          'wear.scores' => ['perm'=>'wear','kind'=>'list','desc'=>'Per-node wear / stress score',
              'params'=>['limit'=>[1,60,15]], 'fields'=>['name','stress','health']],
          'sla.nodes' => ['perm'=>'reports','kind'=>'list','desc'=>'SLA uptime % per node',
              'params'=>['mins'=>[5,43200,1440]], 'fields'=>['name','uptime','outages','meets']],
          'wireguard.peers' => ['perm'=>'wireguard','kind'=>'list','desc'=>'WireGuard peers + connected state',
              'params'=>['limit'=>[1,200,50]], 'fields'=>['name','connected','endpoint','address_ip']],
          'gpu.metrics' => ['perm'=>'gpu','kind'=>'list','desc'=>'AI/GPU servers — utilization, VRAM, temp, power + loaded model',
              'params'=>['limit'=>[1,100,30]], 'fields'=>['target','target_id','gpu','util_pct','vram_used_mb','vram_total_mb','vram_pct','temp_c','power_w','model']],
          'gpu.series' => ['perm'=>'gpu','kind'=>'object','desc'=>'One GPU\'s util/VRAM/temp/power over time (arrays — for line charts)',
              'params'=>['mins'=>[5,1440,60],'target_id'=>[0,9999999,0]], 'fields'=>['name','target','target_id','times','util','vram','temp','power','cur_util','cur_vram','cur_temp','cur_power','model']],
          'syslog.errors' => ['perm'=>'log_mon','kind'=>'list','desc'=>'Recent error-level syslog (severity ≤ 3)',
              'params'=>['limit'=>[1,80,25]], 'fields'=>['at','host','tag','sev','msg']],
        ];
    }

    // Clamp a requested param to the catalog's [min,max,default].
    function _nm_ds_param($spec, $params, $key) {
        if (!isset($spec[$key])) return null;
        [$min,$max,$def] = $spec[$key];
        $v = isset($params[$key]) ? (int)$params[$key] : $def;
        return max($min, min($max, $v));
    }

    // Resolve a data source for the CURRENT user (permission-checked). Never throws
    // raw SQL or upstream errors to the widget — returns ['ok','data'|'error'].
    function nm_ds_resolve($conn, string $id, array $params = []): array {
        nm_widgets_ensure($conn);
        $cat = nm_ds_catalog();
        if (!isset($cat[$id])) return ['ok'=>false,'error'=>'Unknown data source'];
        $src = $cat[$id];
        if (!checkAccess($conn, $src['perm'])) return ['ok'=>false,'error'=>'Not permitted'];
        // lazy-load the engines the broker reaches into (once)
        static $loaded = false;
        if (!$loaded) { $loaded = true;
            foreach (['nm_netflow','nm_wear','nm_sla','nm_health','nm_wireguard'] as $f) {
                $p = __DIR__ . '/' . $f . '.php'; if (is_file($p)) @require_once $p;
            }
        }
        $P = $src['params'];
        try {
            switch ($id) {
                case 'incidents.active':  return ['ok'=>true,'data'=>nm_inc_list($conn, 'active', _nm_ds_param($P,$params,'limit'))];
                case 'nodes.down':        return ['ok'=>true,'data'=>nm_geomap_down($conn)];
                case 'netflow.apps':      return ['ok'=>true,'data'=>nm_nf_top_apps($conn, _nm_ds_param($P,$params,'mins'), '', _nm_ds_param($P,$params,'limit'))];
                case 'netflow.protocols': return ['ok'=>true,'data'=>nm_nf_top_protocols($conn, _nm_ds_param($P,$params,'mins'), '', _nm_ds_param($P,$params,'limit'))];
                case 'netflow.dst':       return ['ok'=>true,'data'=>nm_nf_top_talkers($conn, _nm_ds_param($P,$params,'mins'), 'dst', '', _nm_ds_param($P,$params,'limit'))];
                case 'netflow.summary':   return ['ok'=>true,'data'=>nm_nf_summary($conn, _nm_ds_param($P,$params,'mins'))];
                case 'health.forecasts':  return ['ok'=>true,'data'=>_nm_ds_health($conn, _nm_ds_param($P,$params,'limit'))];
                case 'wear.scores':       return ['ok'=>true,'data'=>array_slice(nm_wear_compute($conn, 30), 0, _nm_ds_param($P,$params,'limit'))];
                case 'sla.nodes':         return ['ok'=>true,'data'=>_nm_ds_sla($conn, _nm_ds_param($P,$params,'mins'))];
                case 'wireguard.peers':   return ['ok'=>true,'data'=>_nm_ds_wg($conn, _nm_ds_param($P,$params,'limit'))];
                case 'gpu.metrics':       return ['ok'=>true,'data'=>_nm_ds_gpu($conn, _nm_ds_param($P,$params,'limit'))];
                case 'gpu.series':        return ['ok'=>true,'data'=>_nm_ds_gpu_series($conn, _nm_ds_param($P,$params,'mins'), _nm_ds_param($P,$params,'target_id'))];
                case 'syslog.errors':     return ['ok'=>true,'data'=>_nm_ds_syslog_err($conn, _nm_ds_param($P,$params,'limit'))];
                case 'nodes.status':      return ['ok'=>true,'data'=>_nm_ds_nodes($conn, _nm_ds_param($P,$params,'limit'))];
                case 'netflow.top':       return ['ok'=>true,'data'=>nm_geomap_netflow($conn, _nm_ds_param($P,$params,'limit'), _nm_ds_param($P,$params,'mins'))];
                case 'interfaces.top':    return ['ok'=>true,'data'=>nm_cmd_top_interfaces($conn, _nm_ds_param($P,$params,'limit'))];
                case 'interfaces.series': return ['ok'=>true,'data'=>_nm_ds_iface_series($conn, _nm_ds_param($P,$params,'limit'), _nm_ds_param($P,$params,'mins'))];
                case 'syslog.recent':     return ['ok'=>true,'data'=>nm_cmd_syslog($conn, _nm_ds_param($P,$params,'limit'))];
                case 'containers.list':   return ['ok'=>true,'data'=>(nm_cmd_container_list($conn)['items'] ?? [])];
                case 'smokeping.latest':  return ['ok'=>true,'data'=>nm_cmd_smokeping($conn, _nm_ds_param($P,$params,'limit'))];
                case 'pihole.top':        return ['ok'=>true,'data'=>nm_cmd_pihole($conn)];
                case 'ping.node':         return ['ok'=>true,'data'=>_nm_ds_ping($conn, _nm_ds_param($P,$params,'node'))];
            }
        } catch (\Throwable $e) { return ['ok'=>false,'error'=>'Source error']; }
        return ['ok'=>false,'error'=>'No resolver'];
    }
    function _nm_ds_nodes($conn, int $limit): array {
        $out = [];
        $r = $conn->query("SELECT n.id, n.display_name name, n.ip_address ip,
                COALESCE((SELECT is_up FROM nm_ping_stats p WHERE p.node_id=n.id ORDER BY p.id DESC LIMIT 1), -1) up
            FROM nm_nodes n ORDER BY n.display_name LIMIT ".(int)$limit);
        while ($r && ($x = $r->fetch_assoc())) $out[] = ['id'=>(int)$x['id'],'name'=>$x['name'],'ip'=>$x['ip'],
            'status'=>($x['up']==-1?'unknown':($x['up']?'up':'down'))];
        return $out;
    }
    function _nm_ds_ping($conn, int $node): array {
        if ($node <= 0) return [];
        $r = $conn->query("SELECT node_id,is_up,latency_ms,packet_loss loss,recorded_at at
            FROM nm_ping_stats WHERE node_id=".(int)$node." ORDER BY id DESC LIMIT 1");
        return ($r && ($x = $r->fetch_assoc())) ? $x : [];
    }
    function _nm_ds_health($conn, int $limit): array {
        $out = []; $limit = max(1, min(100, $limit));
        if (!$conn->query("SHOW TABLES LIKE 'nm_health_predictions'")->num_rows) return $out;
        $r = $conn->query("SELECT p.entity, p.metric, p.severity, p.eta_days, p.detail, n.display_name node
            FROM nm_health_predictions p LEFT JOIN nm_nodes n ON n.id=p.node_id
            WHERE p.status='open' AND p.severity IN ('warn','crit')
            ORDER BY FIELD(p.severity,'crit','warn'), (p.eta_days IS NULL), p.eta_days ASC LIMIT ".(int)$limit);
        while ($r && ($x = $r->fetch_assoc())) $out[] = ['node'=>$x['node'] ?: $x['entity'],'metric'=>$x['metric'],
            'severity'=>$x['severity'],'eta_days'=>$x['eta_days']!==null?round((float)$x['eta_days'],1):null,'detail'=>$x['detail']];
        return $out;
    }
    function _nm_ds_sla($conn, int $mins): array {
        if (!function_exists('nm_sla_all')) return [];
        $out = [];
        foreach (nm_sla_all($conn, $mins) as $n) $out[] = ['name'=>$n['display_name'] ?? '','ip'=>$n['ip_address'] ?? '',
            'uptime'=>$n['uptime'] ?? null,'outages'=>$n['outages'] ?? 0,'down_min'=>$n['down_min'] ?? 0,'meets'=>!empty($n['meets'])];
        return $out;
    }
    function _nm_ds_wg($conn, int $limit): array {
        $out = []; $limit = max(1, min(200, $limit));
        if (!$conn->query("SHOW TABLES LIKE 'nm_wg_peers'")->num_rows) return $out;
        $r = $conn->query("SELECT p.name, p.address_ip, p.endpoint, p.connected, s.name srv
            FROM nm_wg_peers p LEFT JOIN nm_wg_servers s ON s.id=p.server_id
            ORDER BY p.connected DESC, p.name LIMIT ".(int)$limit);
        while ($r && ($x = $r->fetch_assoc())) $out[] = ['name'=>$x['name'],'address_ip'=>$x['address_ip'],
            'endpoint'=>$x['endpoint'],'connected'=>(int)$x['connected'],'server'=>$x['srv']];
        return $out;
    }
    function _nm_ds_gpu($conn, int $limit): array {
        $out = []; $limit = max(1, min(100, $limit));
        if (!$conn->query("SHOW TABLES LIKE 'nm_gpu'")->num_rows) return $out;
        $r = $conn->query("SELECT t.name tname, g.id gid, g.name gname, g.gpu_index, g.target_id
            FROM nm_gpu g JOIN nm_gpu_targets t ON t.id=g.target_id
            ORDER BY t.name, g.gpu_index LIMIT ".(int)$limit);
        while ($r && ($g = $r->fetch_assoc())) {
            $gid=(int)$g['gid']; $tid=(int)$g['target_id'];
            $s  = $conn->query("SELECT util_pct,mem_used_mb,mem_total_mb,temp_c,power_w FROM nm_gpu_stats WHERE gpu_id=$gid ORDER BY id DESC LIMIT 1");
            $st = $s ? ($s->fetch_assoc() ?: []) : [];
            $m  = $conn->query("SELECT name FROM nm_gpu_models WHERE target_id=$tid ORDER BY vram_mb DESC LIMIT 1");
            $model = ($m && ($mr=$m->fetch_assoc())) ? (string)$mr['name'] : '';
            $used=(float)($st['mem_used_mb']??0); $tot=(float)($st['mem_total_mb']??0);
            $out[] = [
                'target'=>$g['tname'], 'target_id'=>$tid, 'gpu'=>$g['gname'] ?: ('GPU'.$g['gpu_index']),
                'util_pct'=>isset($st['util_pct'])&&$st['util_pct']!==null?(float)$st['util_pct']:null,
                'vram_used_mb'=>$used?:null, 'vram_total_mb'=>$tot?:null,
                'vram_pct'=>$tot>0?round(100*$used/$tot,1):null,
                'temp_c'=>isset($st['temp_c'])&&$st['temp_c']!==null?(float)$st['temp_c']:null,
                'power_w'=>isset($st['power_w'])&&$st['power_w']!==null?(float)$st['power_w']:null,
                'model'=>$model,
            ];
        }
        return $out;
    }
    // One GPU's time-series (arrays) for line charts. Picks the given target's first GPU,
    // else the most-recently-sampled GPU. Returns parallel arrays + current (last) values.
    // Top N interfaces (by latest total traffic) each with in/out arrays over `mins`,
    // for line-chart widgets. Rates returned in BITS/sec (raw is bytes/sec → ×8).
    function _nm_ds_iface_series($conn, int $limit, int $mins): array {
        $limit = max(1, min(12, $limit)); $mins = max(5, min(1440, $mins));
        if (!$conn->query("SHOW TABLES LIKE 'nm_port_stats'")->num_rows) return [];
        $tops = [];
        $r = $conn->query("SELECT ps.port_id, (COALESCE(ps.in_rate,0)+COALESCE(ps.out_rate,0)) tot
            FROM nm_port_stats ps
            JOIN (SELECT port_id,MAX(recorded_at) mx FROM nm_port_stats WHERE recorded_at >= (NOW() - INTERVAL 15 MINUTE) GROUP BY port_id) l
              ON ps.port_id=l.port_id AND ps.recorded_at=l.mx
            ORDER BY tot DESC LIMIT $limit");
        while ($r && ($x=$r->fetch_assoc())) $tops[] = (int)$x['port_id'];
        if (!$tops) return [];
        $grp = $mins <= 180
            ? "DATE_FORMAT(recorded_at,'%Y-%m-%d %H:%i:00')"
            : "DATE_FORMAT(DATE_SUB(recorded_at, INTERVAL MINUTE(recorded_at)%30 MINUTE),'%Y-%m-%d %H:%i:00')";
        $out = [];
        foreach ($tops as $pid) {
            $node=''; $iface='';
            $lr = $conn->query("SELECT n.display_name node, COALESCE(NULLIF(i.display_name,''),i.if_name,CONCAT('port ',i.id)) iface
                FROM nm_interfaces i JOIN nm_nodes n ON n.id=i.node_id WHERE i.id=$pid LIMIT 1");
            if ($lr && ($lx=$lr->fetch_assoc())) { $node=(string)$lx['node']; $iface=(string)$lx['iface']; }
            $times=[]; $in=[]; $outA=[];
            $sr = $conn->query("SELECT DATE_FORMAT(MIN(recorded_at),'%Y-%m-%dT%H:%i:%S') ts, ROUND(AVG(in_rate)) i, ROUND(AVG(out_rate)) o
                FROM nm_port_stats WHERE port_id=$pid AND recorded_at >= (NOW() - INTERVAL $mins MINUTE) GROUP BY $grp ORDER BY ts");
            while ($sr && ($sx=$sr->fetch_assoc())) {
                $times[]=$sx['ts'];
                $in[]  = $sx['i']!==null ? round((float)$sx['i']*8) : null;
                $outA[]= $sx['o']!==null ? round((float)$sx['o']*8) : null;
            }
            $last = function($a){ for($i=count($a)-1;$i>=0;$i--) if($a[$i]!==null) return $a[$i]; return 0; };
            $out[] = ['node'=>$node,'iface'=>$iface,'label'=>($node?$node.' · ':'').$iface,
                'times'=>$times,'in'=>$in,'out'=>$outA,'cur_in'=>$last($in),'cur_out'=>$last($outA)];
        }
        return $out;
    }
    function _nm_ds_gpu_series($conn, int $mins, int $target_id): array {
        $mins = max(5, min(1440, $mins));
        if (!$conn->query("SHOW TABLES LIKE 'nm_gpu_stats'")->num_rows) return [];
        if ($target_id > 0) $gr = $conn->query("SELECT id,name,target_id FROM nm_gpu WHERE target_id=".(int)$target_id." ORDER BY gpu_index LIMIT 1");
        else                $gr = $conn->query("SELECT g.id,g.name,g.target_id FROM nm_gpu g JOIN nm_gpu_stats s ON s.gpu_id=g.id ORDER BY s.id DESC LIMIT 1");
        $g = $gr ? $gr->fetch_assoc() : null;
        if (!$g) return [];
        $gid=(int)$g['id']; $tid=(int)$g['target_id'];
        $tname=''; if ($tr=$conn->query("SELECT name FROM nm_gpu_targets WHERE id=$tid LIMIT 1")) { if($x=$tr->fetch_assoc()) $tname=(string)$x['name']; }
        $times=[]; $util=[]; $vram=[]; $temp=[]; $power=[];
        $r = $conn->query("SELECT util_pct,mem_used_mb,mem_total_mb,temp_c,power_w,sampled_at
            FROM nm_gpu_stats WHERE gpu_id=$gid AND sampled_at >= (UTC_TIMESTAMP() - INTERVAL $mins MINUTE) ORDER BY id LIMIT 240");
        while ($r && ($x=$r->fetch_assoc())) {
            $times[]=$x['sampled_at'];
            $util[] =$x['util_pct']!==null?(float)$x['util_pct']:null;
            $vram[] =((float)$x['mem_total_mb']>0)?round(100*(float)$x['mem_used_mb']/(float)$x['mem_total_mb'],1):null;
            $temp[] =$x['temp_c']!==null?(float)$x['temp_c']:null;
            $power[]=$x['power_w']!==null?(float)$x['power_w']:null;
        }
        $cur = function($a){ for($i=count($a)-1;$i>=0;$i--) if($a[$i]!==null) return $a[$i]; return null; };
        $model=''; if ($mr=$conn->query("SELECT name FROM nm_gpu_models WHERE target_id=$tid ORDER BY vram_mb DESC LIMIT 1")) { if($x=$mr->fetch_assoc()) $model=(string)$x['name']; }
        return ['name'=>$g['name'],'target'=>$tname,'target_id'=>$tid,'times'=>$times,'util'=>$util,'vram'=>$vram,'temp'=>$temp,'power'=>$power,
            'cur_util'=>$cur($util),'cur_vram'=>$cur($vram),'cur_temp'=>$cur($temp),'cur_power'=>$cur($power),'model'=>$model];
    }
    function _nm_ds_syslog_err($conn, int $limit): array {
        $out = []; $limit = max(1, min(80, $limit));
        if (!$conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) return $out;
        $r = $conn->query("SELECT received_at, hostname, host_ip, severity, tag, message FROM nm_syslog
            WHERE severity<=3 ORDER BY received_at DESC, id DESC LIMIT ".(int)$limit);
        while ($r && ($x = $r->fetch_assoc())) $out[] = ['at'=>$x['received_at'],'host'=>$x['hostname'] ?: $x['host_ip'],
            'sev'=>(int)$x['severity'],'tag'=>$x['tag'],'msg'=>mb_substr((string)$x['message'],0,180)];
        return $out;
    }

    // ── 2) MANIFEST VALIDATION ─────────────────────────────────────────────────
    // Strict, standards-style: returns ['ok'=>bool,'errors'=>[...],'manifest'=>normalized].
    function nm_widget_validate($m): array {
        $e = [];
        if (!is_array($m)) return ['ok'=>false,'errors'=>['manifest must be a JSON object']];
        if (($m['sdk'] ?? '') !== NM_WIDGET_SDK) $e[] = "sdk must be '".NM_WIDGET_SDK."'";
        $id = (string)($m['id'] ?? '');
        if (!preg_match('/^[a-z0-9]+(?:[._-][a-z0-9]+)+$/i', $id)) $e[] = "id must be namespaced, e.g. 'acme.my-widget'";
        $name = trim((string)($m['name'] ?? ''));
        if ($name === '' || mb_strlen($name) > 120) $e[] = 'name required (≤120 chars)';
        $kind = $m['kind'] ?? 'declarative';
        if (!in_array($kind, ['declarative','code'], true)) $e[] = "kind must be 'declarative' or 'code'";
        $refresh = isset($m['refresh']) ? (int)$m['refresh'] : 20;
        if ($refresh < 5 || $refresh > 3600) $e[] = 'refresh must be 5–3600 seconds';
        // needs[] — every declared source must exist in the catalog
        $cat = nm_ds_catalog(); $asNames = [];
        foreach ((array)($m['needs'] ?? []) as $i => $n) {
            if (!is_array($n) || !isset($n['source'])) { $e[] = "needs[$i] missing 'source'"; continue; }
            if (!isset($cat[$n['source']])) $e[] = "needs[$i] unknown source '".$n['source']."'";
            $as = $n['as'] ?? $n['source'];
            if (!preg_match('/^[a-z_][a-z0-9_]*$/i', (string)$as)) $e[] = "needs[$i] invalid alias '$as'";
            $asNames[$as] = true;
        }
        if ($kind === 'declarative') {
            $v = $m['view'] ?? null;
            if (!is_array($v)) $e[] = 'declarative widget needs a view object';
            else {
                $vt = $v['type'] ?? '';
                if (!in_array($vt, ['stat','gauge','trend','lines','charts','list','bar','table','alarm','sonify','gpu'], true)) $e[] = "view.type must be stat|gauge|trend|lines|charts|list|bar|table|alarm|sonify|gpu";
                if (isset($v['from']) && !isset($asNames[$v['from']])) $e[] = "view.from '".$v['from']."' is not a declared need";
                if ($vt === 'alarm' && !is_numeric($v['threshold'] ?? null)) $e[] = "alarm view needs a numeric 'threshold'";
            }
        } else { // code
            $entry = (string)($m['entry'] ?? '');
            if ($entry === '') $e[] = 'code widget needs an entry script';
            if (strlen($entry) > 200000) $e[] = 'entry too large (>200KB)';
        }
        if ($e) return ['ok'=>false,'errors'=>$e];
        // normalized manifest (fill defaults)
        $m['sdk'] = NM_WIDGET_SDK; $m['kind'] = $kind; $m['refresh'] = $refresh;
        $m['icon'] = (string)($m['icon'] ?? 'fa-puzzle-piece');
        return ['ok'=>true,'errors'=>[],'manifest'=>$m];
    }

    // ── 3) REGISTRY (DB-backed install/list/remove) ────────────────────────────
    function nm_widgets_list($conn, int $uid): array {
        nm_widgets_ensure($conn);
        $uid = (int)$uid; $out = [];
        $r = $conn->query("SELECT widget_id,owner_uid,scope,name,manifest,enabled FROM nm_widgets
            WHERE enabled=1 AND (scope='global' OR owner_uid=$uid) ORDER BY scope DESC, name");
        while ($r && ($x = $r->fetch_assoc())) {
            $man = json_decode($x['manifest'], true);
            if (is_array($man)) $out[] = ['widget_id'=>$x['widget_id'],'scope'=>$x['scope'],
                'owner_uid'=>(int)$x['owner_uid'],'name'=>$x['name'],'manifest'=>$man,'mine'=>((int)$x['owner_uid']===$uid)];
        }
        return $out;
    }
    // $scope='global' only honored when $canGlobal (caller passes admin check).
    function nm_widget_install($conn, int $uid, $manifest, string $scope = 'user', bool $canGlobal = false): array {
        nm_widgets_ensure($conn);
        $val = nm_widget_validate($manifest);
        if (!$val['ok']) return ['ok'=>false,'errors'=>$val['errors']];
        $m = $val['manifest'];
        $scope = ($scope === 'global' && $canGlobal) ? 'global' : 'user';
        $json = json_encode($m, JSON_UNESCAPED_SLASHES);
        if ($json === false || strlen($json) > 250000) return ['ok'=>false,'errors'=>['manifest too large']];
        $st = $conn->prepare("INSERT INTO nm_widgets (widget_id,owner_uid,scope,name,manifest,enabled)
            VALUES (?,?,?,?,?,1)
            ON DUPLICATE KEY UPDATE scope=VALUES(scope),name=VALUES(name),manifest=VALUES(manifest),enabled=1");
        $st->bind_param('sisss', $m['id'], $uid, $scope, $m['name'], $json);
        $st->execute(); $st->close();
        return ['ok'=>true,'widget_id'=>$m['id'],'scope'=>$scope];
    }
    // ONLY the creator may delete their widget (NEURU official widgets aren't in this
    // table at all, so they can never be deleted). $isAdmin kept for signature compat
    // but intentionally ignored — creator-only by design.
    function nm_widget_remove($conn, int $uid, string $widgetId, bool $isAdmin = false): array {
        nm_widgets_ensure($conn);
        $st = $conn->prepare("DELETE FROM nm_widgets WHERE widget_id=? AND owner_uid=".(int)$uid." LIMIT 1");
        $st->bind_param('s', $widgetId); $st->execute();
        $n = $st->affected_rows; $st->close();
        return ['ok'=>$n>0];
    }

    // ── MARKETPLACE ────────────────────────────────────────────────────────────
    // Official NEURU widgets: a curated, code-complete set (author "NEURU"). They
    // double as ready-to-install widgets AND as worked examples to learn from.
    // They live in code (not the DB), so they can never be deleted.
    function nm_widgets_official(): array {
        $w = [];
        $mk = function($id,$name,$icon,$cat,$desc,$refresh,$needs,$view) {
            return ['sdk'=>'1.0','id'=>$id,'name'=>$name,'icon'=>$icon,'author'=>'NEURU','category'=>$cat,
                'description'=>$desc,'refresh'=>$refresh,'needs'=>$needs,'kind'=>'declarative','view'=>$view];
        };
        $w[] = $mk('neuru.open-incidents','Open Incidents','fa-triangle-exclamation','Incidents',
            'A single number: how many incidents are open or acknowledged, colored green/amber/red.',20,
            [['source'=>'incidents.active','as'=>'inc']],
            ['type'=>'stat','from'=>'inc','agg'=>'count','label'=>'open incidents','thresholds'=>[1,3]]);
        $w[] = $mk('neuru.incident-feed','Incident Feed','fa-list','Incidents',
            'Live list of open incidents with severity and the affected entity.',20,
            [['source'=>'incidents.active','as'=>'inc','params'=>['limit'=>15]]],
            ['type'=>'list','from'=>'inc','title'=>'{title}','subtitle'=>'{root_entity} · {status}','badge'=>'{severity}']);
        $w[] = $mk('neuru.top-talkers','Top Talkers','fa-fire','NetFlow',
            'Bar chart of the busiest source IPs by bandwidth (Mb/s).',20,
            [['source'=>'netflow.top','as'=>'nf','params'=>['limit'=>8]]],
            ['type'=>'bar','from'=>'nf','label'=>'{ip}','value'=>'{mbps}','limit'=>8]);
        $w[] = $mk('neuru.top-apps','Top Applications','fa-layer-group','NetFlow',
            'Bar chart of the top applications/ports by bandwidth.',30,
            [['source'=>'netflow.apps','as'=>'a','params'=>['limit'=>8]]],
            ['type'=>'bar','from'=>'a','label'=>'{app}','value'=>'{mbps}','limit'=>8]);
        $w[] = $mk('neuru.busy-interfaces','Busiest Interfaces','fa-ethernet','Traffic',
            'Interfaces ranked by total throughput.',20,
            [['source'=>'interfaces.top','as'=>'i','params'=>['limit'=>8]]],
            ['type'=>'bar','from'=>'i','label'=>'{iface}','value'=>'{total}','limit'=>8]);
        $w[] = $mk('neuru.iface-traffic','Top Interface Traffic','fa-chart-line','Traffic',
            'The top interfaces as live IN/OUT traffic line charts (last hour), each labeled by node — real graphs, not bars.',20,
            [['source'=>'interfaces.series','as'=>'i','params'=>['limit'=>5,'mins'=>60]]],
            ['type'=>'charts','from'=>'i','title'=>'{label}','unit'=>'bps','limit'=>5,'series'=>[
                ['field'=>'in','label'=>'In','color'=>'#4da3ff'],
                ['field'=>'out','label'=>'Out','color'=>'#2ecc71'],
            ]]);
        $w[] = $mk('neuru.nodes-down','Nodes Down','fa-plug-circle-xmark','Availability',
            'List of nodes that are currently unreachable.',15,
            [['source'=>'nodes.down','as'=>'d']],
            ['type'=>'list','from'=>'d','title'=>'{name}','subtitle'=>'{ip}']);
        $w[] = $mk('neuru.latency-watch','Latency Watch','fa-wave-square','Performance',
            'Per-node latest round-trip time from Smokeping.',30,
            [['source'=>'smokeping.latest','as'=>'s','params'=>['limit'=>10]]],
            ['type'=>'list','from'=>'s','title'=>'{name}','subtitle'=>'{rtt} ms (avg {avg})']);
        $w[] = $mk('neuru.predictive','Predictive Health','fa-heart-pulse','Health',
            'What is forecast to degrade, and in how many days.',60,
            [['source'=>'health.forecasts','as'=>'h','params'=>['limit'=>10]]],
            ['type'=>'list','from'=>'h','title'=>'{node} · {metric}','subtitle'=>'in {eta_days} days — {detail}','badge'=>'{severity}']);
        $w[] = $mk('neuru.sla-board','SLA Leaderboard','fa-gauge-high','Reports',
            'Uptime % per node as a table (worst first).',120,
            [['source'=>'sla.nodes','as'=>'sla','params'=>['mins'=>1440]]],
            ['type'=>'table','from'=>'sla','columns'=>[['label'=>'Node','field'=>'name'],['label'=>'Uptime %','field'=>'uptime'],['label'=>'Outages','field'=>'outages']]]);
        $w[] = $mk('neuru.wg-peers','WireGuard Peers','fa-shield-halved','Network',
            'VPN peers and whether they are connected.',30,
            [['source'=>'wireguard.peers','as'=>'wg','params'=>['limit'=>20]]],
            ['type'=>'list','from'=>'wg','title'=>'{name}','subtitle'=>'{endpoint} · {address_ip}','badge'=>'{connected}']);
        $w[] = $mk('neuru.gpu-load','GPU Load','fa-microchip','AI / GPU',
            'Rich per-GPU panel: utilization (with live sparkline), VRAM bar, temperature, power and the loaded Ollama model — links to the full GPU Monitor.',15,
            [['source'=>'gpu.metrics','as'=>'g','params'=>['limit'=>4]]],
            ['type'=>'gpu','from'=>'g','limit'=>4]);
        $w[] = $mk('neuru.gpu-util','GPU Utilization','fa-gauge-high','AI / GPU',
            'Peak GPU utilization across all AI servers as a gauge (green/amber/red bar).',15,
            [['source'=>'gpu.metrics','as'=>'g','params'=>['limit'=>20]]],
            ['type'=>'gauge','from'=>'g','agg'=>'max:util_pct','label'=>'GPU','unit'=>'%','max'=>100,'thresholds'=>[70,90]]);
        $w[] = $mk('neuru.gpu-graphs','GPU Graphs','fa-chart-line','AI / GPU',
            'Full GPU telemetry as live line charts — utilization, VRAM %, temperature and power over time, with the loaded model. Links to the GPU Monitor.',20,
            [['source'=>'gpu.series','as'=>'g','params'=>['mins'=>60]]],
            ['type'=>'lines','from'=>'g','title'=>'target','subtitle'=>'name','link'=>'gpu.php','series'=>[
                ['field'=>'util','label'=>'GPU','unit'=>'%','color'=>'#76b900','max'=>100],
                ['field'=>'vram','label'=>'VRAM','unit'=>'%','color'=>'#4da3ff','max'=>100],
                ['field'=>'temp','label'=>'Temp','unit'=>'°C','color'=>'#f39c12'],
                ['field'=>'power','label'=>'Power','unit'=>'W','color'=>'#9b59b6'],
            ]]);
        $w[] = $mk('neuru.bandwidth-trend','Bandwidth Trend','fa-chart-line','NetFlow',
            'A live graph of total attributed bandwidth — example of the generic Trend visual you can build on ANY data source.',15,
            [['source'=>'netflow.summary','as'=>'nf']],
            ['type'=>'trend','from'=>'nf','value'=>'{avg_mbps}','label'=>'total','unit'=>'Mb/s']);
        $w[] = $mk('neuru.syslog-errors','Error Logs','fa-file-circle-exclamation','Logs',
            'Most recent error-level syslog lines (severity ≤ 3).',20,
            [['source'=>'syslog.errors','as'=>'e','params'=>['limit'=>15]]],
            ['type'=>'list','from'=>'e','title'=>'{host} · {tag}','subtitle'=>'{msg}']);
        $w[] = $mk('neuru.containers','Containers','fa-cubes','Containers',
            'List of containers with their state and host.',30,
            [['source'=>'containers.list','as'=>'c']],
            ['type'=>'list','from'=>'c','title'=>'{name}','subtitle'=>'{host} · {image}','badge'=>'{state}']);
        $w[] = $mk('neuru.network-pulse','Network Pulse','fa-satellite-dish','Sonar',
            'Companion to Network Sonar: how many nodes are down right now (green = all up, red = any down).',15,
            [['source'=>'nodes.down','as'=>'d']],
            ['type'=>'stat','from'=>'d','agg'=>'count','label'=>'nodes down','thresholds'=>[1,1]]);
        $w[] = $mk('neuru.down-alarm','Down-Node Alarm','fa-bell','Sound',
            'Sounds a two-tone alarm and flashes red when ANY node goes down. Muted until you arm it.',15,
            [['source'=>'nodes.down','as'=>'d']],
            ['type'=>'alarm','from'=>'d','agg'=>'count','label'=>'nodes down','compare'=>'>=','threshold'=>1]);
        $w[] = $mk('neuru.bandwidth-sonify','Bandwidth Sonify','fa-wave-square','Sound',
            'A live tone whose pitch tracks total bandwidth — hear traffic rise and fall. Muted until armed.',15,
            [['source'=>'netflow.summary','as'=>'nf']],
            ['type'=>'sonify','from'=>'nf','value'=>'{avg_mbps}','label'=>'total Mb/s']);
        return $w;
    }

    // The marketplace payload: official (NEURU) + community (user-authored) widgets.
    function nm_widgets_marketplace($conn, int $uid): array {
        nm_widgets_ensure($conn);
        $official = nm_widgets_official();
        $offIds = array_column($official, 'id');
        foreach ($official as &$m) { $m['_author']='NEURU'; $m['_source']='neuru'; $m['_mine']=false; } unset($m);
        $community = [];
        $r = $conn->query("SELECT w.widget_id,w.owner_uid,w.scope,w.manifest, u.USERNAME author
            FROM nm_widgets w LEFT JOIN users u ON u.UID=w.owner_uid
            WHERE w.enabled=1 ORDER BY w.created_at DESC");
        while ($r && ($x = $r->fetch_assoc())) {
            if (in_array($x['widget_id'], $offIds, true)) continue;   // a user's copy of an official → don't list as community
            $man = json_decode($x['manifest'], true); if (!is_array($man)) continue;
            $man['_author'] = $x['author'] ?: ('user ' . (int)$x['owner_uid']);
            $man['_source'] = 'community';
            $man['_mine']   = ((int)$x['owner_uid'] === $uid);
            $man['_scope']  = $x['scope'];
            $community[] = $man;
        }
        return ['official'=>array_values($official), 'community'=>$community];
    }
}
