<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Weather-Aware Routing engine. Physical networks suffer from real-world
// weather (tropical storms, hurricanes, rain-fade on microwave links, grid
// flicker). NEURU geolocates field nodes; an n8n flow polls a weather API (e.g.
// NWS api.weather.gov — free, covers Puerto Rico) per node point and posts back
// active alerts. NEURU marks threatened nodes, scores risk, and (advisory v1)
// recommends a proactive failover BEFORE the node loses power / link.
// Page gate = permission key 'weather'.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_wx_threatened')) {

    function nm_wx_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done=false; if($done) return; $done=true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_node_geo (
            node_id INT PRIMARY KEY, lat DOUBLE NOT NULL, lon DOUBLE NOT NULL,
            link_type VARCHAR(16) DEFAULT 'fiber',   -- fiber | microwave | satellite | copper
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_weather_alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ext_id VARCHAR(120) DEFAULT NULL,
            node_id INT DEFAULT NULL,
            event VARCHAR(120) NOT NULL,
            severity VARCHAR(12) NOT NULL DEFAULT 'moderate',  -- minor|moderate|severe|extreme
            headline VARCHAR(400) DEFAULT NULL,
            lat DOUBLE DEFAULT NULL, lon DOUBLE DEFAULT NULL, radius_km DOUBLE DEFAULT NULL,
            effective DATETIME DEFAULT NULL, expires DATETIME DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_alert (ext_id, node_id), KEY idx_exp (expires)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','weather',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='weather')");
    }
    function nm_wx_setting($conn,$k,$d){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }
    function _wx_sev_rank($s){ return ['minor'=>1,'moderate'=>2,'severe'=>3,'extreme'=>4][strtolower($s)] ?? 2; }
    function _wx_hav($la1,$lo1,$la2,$lo2){ $R=6371; $dla=deg2rad($la2-$la1); $dlo=deg2rad($lo2-$lo1);
        $a=sin($dla/2)**2 + cos(deg2rad($la1))*cos(deg2rad($la2))*sin($dlo/2)**2; return $R*2*atan2(sqrt($a),sqrt(1-$a)); }

    // Nodes with geo (for n8n to query weather per point).
    function nm_wx_nodes_geo($conn): array {
        nm_wx_ensure($conn); $o=[];
        $r=$conn->query("SELECT g.node_id, g.lat, g.lon, g.link_type, n.display_name FROM nm_node_geo g JOIN nm_nodes n ON n.id=g.node_id");
        while($r&&$x=$r->fetch_assoc()) $o[]=['id'=>(int)$x['node_id'],'name'=>$x['display_name'],'lat'=>(float)$x['lat'],'lon'=>(float)$x['lon'],'link_type'=>$x['link_type']];
        return $o;
    }
    function nm_wx_set_geo($conn,int $nodeId,$lat,$lon,$linkType='fiber'): void {
        nm_wx_ensure($conn);
        $lt=in_array($linkType,['fiber','microwave','satellite','copper'],true)?$linkType:'fiber';
        $st=$conn->prepare("INSERT INTO nm_node_geo (node_id,lat,lon,link_type) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE lat=VALUES(lat),lon=VALUES(lon),link_type=VALUES(link_type)");
        $la=(float)$lat; $lo=(float)$lon; $st->bind_param('idds',$nodeId,$la,$lo,$lt); $st->execute();
    }
    function nm_wx_del_geo($conn,int $nodeId){ $conn->query("DELETE FROM nm_node_geo WHERE node_id=".(int)$nodeId); }

    // Ingest alerts from n8n. Each: {ext_id?, node_id?|lat/lon/radius_km, event, severity, headline, effective, expires}.
    function nm_wx_ingest($conn, array $alerts): array {
        nm_wx_ensure($conn);
        $geo=nm_wx_nodes_geo($conn); $n=0;
        foreach($alerts as $a){
            $event=substr((string)($a['event']??'Weather alert'),0,120);
            $sev=in_array(strtolower((string)($a['severity']??'')),['minor','moderate','severe','extreme'],true)?strtolower($a['severity']):'moderate';
            $head=substr((string)($a['headline']??''),0,400); $ext=substr((string)($a['ext_id']??sha1($event.$head.($a['expires']??''))),0,120);
            $eff=!empty($a['effective'])?date('Y-m-d H:i:s',strtotime($a['effective'])):null;
            $exp=!empty($a['expires'])?date('Y-m-d H:i:s',strtotime($a['expires'])):date('Y-m-d H:i:s',time()+6*3600);
            $lat=isset($a['lat'])?(float)$a['lat']:null; $lon=isset($a['lon'])?(float)$a['lon']:null; $rad=isset($a['radius_km'])?(float)$a['radius_km']:50;
            // resolve affected nodes
            $targets=[];
            if(!empty($a['node_id'])) $targets[]=(int)$a['node_id'];
            elseif($lat!==null && $lon!==null){ foreach($geo as $g){ if(_wx_hav($lat,$lon,$g['lat'],$g['lon'])<=$rad) $targets[]=$g['id']; } }
            else $targets[]=null; // area-wide alert with no geo → store unattached
            if(!$targets) $targets[]=null;
            foreach($targets as $nid){
                $st=$conn->prepare("INSERT INTO nm_weather_alerts (ext_id,node_id,event,severity,headline,lat,lon,radius_km,effective,expires)
                    VALUES (?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE event=VALUES(event),severity=VALUES(severity),headline=VALUES(headline),expires=VALUES(expires)");
                $st->bind_param('sisssdddss',$ext,$nid,$event,$sev,$head,$lat,$lon,$rad,$eff,$exp); $st->execute(); $n++;
            }
        }
        // prune expired
        $conn->query("DELETE FROM nm_weather_alerts WHERE expires IS NOT NULL AND expires < NOW()");
        return ['ingested'=>$n];
    }

    // Threatened nodes = geo nodes with an active alert; severity-ranked + advice.
    function nm_wx_threatened($conn): array {
        nm_wx_ensure($conn);
        $o=[];
        $r=$conn->query("SELECT a.node_id, n.display_name, g.link_type, MAX(a.severity) sev_any,
                MAX(a.event) ev, MAX(a.headline) hl, MIN(a.expires) exp,
                (SELECT severity FROM nm_weather_alerts b WHERE b.node_id=a.node_id AND b.expires>NOW() ORDER BY FIELD(b.severity,'extreme','severe','moderate','minor') LIMIT 1) topsev
            FROM nm_weather_alerts a JOIN nm_nodes n ON n.id=a.node_id LEFT JOIN nm_node_geo g ON g.node_id=a.node_id
            WHERE a.node_id IS NOT NULL AND a.expires>NOW() GROUP BY a.node_id");
        while($r&&$x=$r->fetch_assoc()){
            $sev=$x['topsev']?:'moderate'; $lt=$x['link_type']?:'fiber';
            $rainFade = in_array($lt,['microwave','satellite'],true) && _wx_sev_rank($sev)>=2;
            $advice = _wx_sev_rank($sev)>=3
                ? ('Pre-stage failover for '.$x['display_name'].($rainFade?' (rain-fade risk on '.$lt.' link)':'').' — divert critical traffic before impact.')
                : ('Monitor '.$x['display_name'].($rainFade?' — '.$lt.' link may degrade (rain-fade)':'').'.');
            $o[]=['node_id'=>(int)$x['node_id'],'name'=>$x['display_name'],'link_type'=>$lt,'severity'=>$sev,
                'event'=>$x['ev'],'headline'=>$x['hl'],'expires'=>$x['exp'],'rain_fade'=>$rainFade,'advice'=>$advice];
        }
        usort($o, fn($a,$b)=>_wx_sev_rank($b['severity'])<=>_wx_sev_rank($a['severity']));
        return $o;
    }
    function nm_wx_active_alerts($conn): array {
        nm_wx_ensure($conn); $o=[];
        $r=$conn->query("SELECT DISTINCT event,severity,headline,MIN(effective) eff,MAX(expires) exp,COUNT(DISTINCT node_id) nodes FROM nm_weather_alerts WHERE expires>NOW() GROUP BY event,severity,headline ORDER BY FIELD(severity,'extreme','severe','moderate','minor')");
        while($r&&$x=$r->fetch_assoc()) $o[]=$x;
        return $o;
    }
    function nm_wx_counts($conn): array {
        nm_wx_ensure($conn);
        $a=$conn->query("SELECT COUNT(*) FROM nm_weather_alerts WHERE expires>NOW()")->fetch_row()[0];
        $t=count(nm_wx_threatened($conn)); $g=count(nm_wx_nodes_geo($conn));
        return ['alerts'=>(int)$a,'threatened'=>$t,'geo_nodes'=>$g];
    }

    // Trigger the n8n weather poll (sends node geo so n8n can query per point).
    function nm_wx_poll($conn): array {
        $url=nm_wx_setting($conn,'wx_poll_url',''); if($url==='' || !function_exists('curl_init')) return ['ok'=>false,'err'=>'wx_poll_url not set'];
        $cfg=nm_n8n_get($conn); $base=function_exists('nm_n8n_callback_base')?nm_n8n_callback_base($conn,$url):(((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http').'://'.($_SERVER['HTTP_HOST']??'localhost'));  // per-flow: hosted→tunnel, local→LAN
        $payload=['nodes'=>nm_wx_nodes_geo($conn),'alerts_url'=>$base.'/nm_weather_api.php?ep=alerts'];
        if(function_exists('nm_n8n_neuru_stamp'))$payload=nm_n8n_neuru_stamp($conn,$payload,$url);  // hosted-flow gatecheck
        $ch=curl_init($url);
        curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload),CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_TIMEOUT=>20,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>false,CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]);
        curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        return ['ok'=>($code>=200&&$code<300),'code'=>$code];
    }
}
