<?php
require_once __DIR__ . '/nm_config.php';
// ─── LibreNMS config — sourced from the DB (nm_settings), not a web-root file ──
require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_lnms.php';
require_once __DIR__ . '/nm_graylog.php';
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_secrets.php';
require_once __DIR__ . '/nm_portainer.php';
require_once __DIR__ . '/nm_geomap.php';   // node geo (coords) + GeoIP auto-locate
require_once __DIR__ . '/nm_nodemeta.php'; // device classification + asset fields (model/serial/warranty/photo)
require_once __DIR__ . '/nm_media.php';    // secure image upload (equipment photos)
require_once __DIR__ . '/nm_license.php';  // node-limit enforcement (best-effort; no-op unless enforced)
nm_node_meta_ensure($conn);
$_lnms_cfg = nm_lnms_get($conn);

// Sanitize the industry-standard asset fields from a node add/edit POST.
function nm_cfg_read_asset(array $src): array {
    $s = fn($k,$len)=> (substr(trim((string)($src[$k]??'')),0,$len) ?: null);
    $d = function($k) use($src){ $v=trim((string)($src[$k]??'')); return preg_match('/^\d{4}-\d{2}-\d{2}$/',$v)?$v:null; };
    return [
        'manufacturer'    => $s('manufacturer',120),
        'model'           => $s('model',120),
        'serial_number'   => $s('serial_number',120),
        'asset_tag'       => $s('asset_tag',80),
        'purchase_date'   => $d('purchase_date'),
        'warranty_expiry' => $d('warranty_expiry'),
        'asset_notes'     => (substr(trim((string)($src['asset_notes']??'')),0,2000) ?: null),
    ];
}

// GeoIP auto-locate endpoint for the node coordinate form (public IPs only).
if (($_GET['api'] ?? '') === 'node_geoip') {
    header('Content-Type: application/json; charset=utf-8');
    $ip = trim($_GET['ip'] ?? '');
    $g  = $ip !== '' ? nm_nt_geoip($conn, $ip) : null;
    if ($g && empty($g['private'])) echo json_encode(['ok'=>true,'lat'=>$g['lat'],'lon'=>$g['lon'],'city'=>$g['city']??'','country'=>$g['country']??'']);
    else echo json_encode(['ok'=>false,'error'=>$g && !empty($g['private']) ? 'Private IP — set coordinates manually' : 'No geolocation for this IP']);
    exit;
}
nm_geomap_ensure($conn);
$geoMap = [];   // node_id => {lat,lon,city,country,link_type} for the node edit form
$gr = $conn->query("SELECT node_id,lat,lon,city,country,link_type FROM nm_node_geo");
while ($gr && ($gx = $gr->fetch_assoc())) $geoMap[(int)$gx['node_id']] = $gx;
define('NMC_URL',   $_lnms_cfg['url']);
define('NMC_TOKEN', $_lnms_cfg['token']);

function nmc_call($ep, $p=[]) {
    $q  = $p ? '?'.http_build_query($p) : '';
    $ch = curl_init(NMC_URL.$ep.$q);
    curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>3,
        CURLOPT_TIMEOUT=>6,CURLOPT_HTTPHEADER=>['X-Auth-Token: '.NMC_TOKEN]]);
    $r = curl_exec($ch); curl_close($ch);
    return $r ? json_decode($r,true) : null;
}

// ─── AJAX endpoints (before any output / includes) ────────────────────────────
if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');

    // Audit every state-changing (POST) config action. Does NOT read php://input
    // (handlers below consume it), only the action name — enough for "who changed
    // what, when". Status/target detail can be enriched per-handler later.
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        if (session_status() === PHP_SESSION_NONE) session_start();
        include_once __DIR__ . '/connection.php';
        require_once __DIR__ . '/nm_audit.php';
        nm_audit($conn, 'config.' . preg_replace('/[^a-z0-9_]/i', '', (string)$_GET['api']), [
            'target_type' => 'config',
            'username'    => $_SESSION['username'] ?? null,
        ]);
    }

    switch ($_GET['api']) {
        case 'test':
            $r = nmc_call('/api/v0/system');
            echo json_encode($r && isset($r['status'])
                ? ['ok'=>true,'ver'=>$r['librenms_ver']??'?','db'=>$r['db_schema']??'?']
                : ['ok'=>false,'err'=>'Cannot reach '.NMC_URL]);
            break;
        case 'devices':
            $r = nmc_call('/api/v0/devices');
            echo json_encode(['devices'=>$r['devices']??[],'err'=>isset($r)?null:'No response']);
            break;
        case 'interfaces':
            $id = (int)($_GET['device_id']??0);
            $r  = nmc_call("/api/v0/devices/{$id}/ports",['columns'=>'port_id,ifName,ifDescr,ifAlias,ifOperStatus,ifAdminStatus,ifSpeed,ifType']);
            echo json_encode(['ports'=>$r['ports']??[]]);
            break;
        case 'saved_ifaces':
            include_once('connection.php');
            $nid = (int)($_GET['node_id']??0);
            $ids = [];
            if ($nid) {
                $res = $conn->query("SELECT lnms_port_id FROM nm_interfaces WHERE node_id={$nid}");
                while ($row=$res->fetch_row()) $ids[]=(int)$row[0];
            }
            echo json_encode(['ids'=>$ids]);
            break;
        case 'save_ifaces':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body  = json_decode(file_get_contents('php://input'), true) ?? [];
            $nid   = (int)($body['node_id'] ?? 0);
            $ports = $body['ports']         ?? [];
            if ($nid) {
                $conn->query("DELETE FROM nm_interfaces WHERE node_id={$nid}");
                $sort = 0;
                foreach ($ports as $port) {
                    $pid = (int)($port['pid'] ?? 0);
                    if (!$pid) continue;
                    $ifn = substr(trim($port['if_name']      ?? ''), 0, 100);
                    $ifa = substr(trim($port['if_alias']     ?? ''), 0, 200);
                    $dsp = substr(trim($port['display_name'] ?? ($ifa ?: $ifn)), 0, 100);
                    $gr  = ($port['show_graph'] ?? 0) ? 1 : 0;
                    $st  = $conn->prepare("INSERT INTO nm_interfaces(node_id,lnms_port_id,if_name,if_alias,display_name,show_graph,sort_order) VALUES(?,?,?,?,?,?,?)");
                    $st->bind_param('iisssii', $nid, $pid, $ifn, $ifa, $dsp, $gr, $sort);
                    $st->execute();
                    $sort++;
                }
                echo json_encode(['ok'=>true,'saved'=>$sort]);
            } else {
                echo json_encode(['ok'=>false,'err'=>'Invalid node ID']);
            }
            break;
        case 'run_poller':
            if (session_status()===PHP_SESSION_NONE) session_start();
            if (empty($_SESSION['username'])) { echo json_encode(['err'=>'Unauthorized']); break; }
            $py   = escapeshellarg(VENV_PYTHON);
            $snmp = escapeshellarg(SCRIPTS_DIR . '/nm_poller.py');
            $ping = escapeshellarg(SCRIPTS_DIR . '/nm_ping.py');
            // Run the ping poller first (fast), then the SNMP poller. `timeout` caps
            // each so an unreachable SNMP device can't hang the request/browser.
            $out  = shell_exec("timeout 25 $py $ping 2>&1");
            $out .= "\n" . shell_exec("timeout 90 $py $snmp 2>&1");
            echo json_encode(['output' => trim($out) ?: 'No output']);
            break;
        case 'list_templates':
            include_once('connection.php');
            $res = $conn->query("SELECT t.id,t.name,t.os_type,t.description,t.is_builtin,
                (SELECT COUNT(*) FROM nm_oid_configs WHERE template_id=t.id) oid_count
                FROM nm_oid_templates t ORDER BY t.is_builtin DESC, t.name");
            echo json_encode(['templates'=> $res ? $res->fetch_all(MYSQLI_ASSOC) : []]);
            break;
        case 'template_oids':
            include_once('connection.php');
            $tid = (int)($_GET['template_id']??0);
            $res = $conn->query("SELECT * FROM nm_oid_configs WHERE template_id={$tid} ORDER BY sort_order,id");
            echo json_encode(['oids'=> $res ? $res->fetch_all(MYSQLI_ASSOC) : []]);
            break;
        case 'node_oids':
            include_once('connection.php');
            $nid = (int)($_GET['node_id']??0);
            // Get node's assigned template OIDs + node-specific OIDs
            $res = $conn->query("
                SELECT oc.*, NULL as source_label
                FROM nm_oid_configs oc
                WHERE oc.node_id={$nid}
                ORDER BY oc.sort_order,oc.id
            ");
            $node_oids = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
            // Get template info for this node
            $nr = $conn->query("SELECT oid_template_id FROM nm_nodes WHERE id={$nid} LIMIT 1");
            $tpl_id = $nr ? ((int)($nr->fetch_assoc()['oid_template_id'] ?? 0)) : 0;
            echo json_encode(['oids'=> $node_oids, 'template_id'=> $tpl_id]);
            break;
        case 'save_node_template':
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $nid  = (int)($body['node_id']     ?? 0);
            $tid  = ($body['template_id'] !== null && $body['template_id'] !== '') ? (int)$body['template_id'] : null;
            if ($nid) {
                $st = $conn->prepare("UPDATE nm_nodes SET oid_template_id=? WHERE id=?");
                $st->bind_param('ii', $tid, $nid);
                $st->execute();
                echo json_encode(['ok'=>true]);
            } else {
                echo json_encode(['ok'=>false,'err'=>'Invalid node']);
            }
            break;
        case 'save_oid':
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body  = json_decode(file_get_contents('php://input'), true) ?? [];
            $nid   = (int)($body['node_id']     ?? 0);
            $tid   = ($body['template_id']  ?? null) ? (int)$body['template_id'] : null;
            $mname = substr(trim($body['metric_name'] ?? ''), 0, 100);
            $mtype = in_array($body['metric_type'] ?? '', ['cpu','memory','disk','temperature','uptime','custom'])
                     ? $body['metric_type'] : 'custom';
            $oid   = substr(trim($body['oid']       ?? ''), 0, 200);
            $otot  = substr(trim($body['oid_total'] ?? ''), 0, 200) ?: null;
            $unit  = substr(trim($body['unit']      ?? '%'), 0, 20);
            $walk  = ($body['walk'] ?? 0) ? 1 : 0;
            $scale = min(1e6, max(1e-6, (float)($body['scale'] ?? 1.0)));
            $desc  = substr(trim($body['description'] ?? ''), 0, 300);
            $sort  = (int)($body['sort_order'] ?? 0);
            if (!$oid || !$mname || (!$nid && !$tid)) {
                echo json_encode(['ok'=>false,'err'=>'Missing required fields']);
                break;
            }
            $st = $conn->prepare("INSERT INTO nm_oid_configs
                (template_id,node_id,metric_name,metric_type,oid,oid_total,unit,walk,scale,description,sort_order)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)");
            $st->bind_param('iisssssidsi', $tid, $nid, $mname, $mtype, $oid, $otot, $unit, $walk, $scale, $desc, $sort);
            $st->execute();
            echo json_encode(['ok'=>true,'id'=>$conn->insert_id]);
            break;
        case 'del_oid':
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $id   = (int)($body['id'] ?? 0);
            if ($id) {
                // Only allow deleting non-builtin (template_id whose is_builtin=0 OR node_id OIDs)
                $chk = $conn->query("SELECT oc.id, t.is_builtin
                    FROM nm_oid_configs oc
                    LEFT JOIN nm_oid_templates t ON t.id=oc.template_id
                    WHERE oc.id={$id} LIMIT 1");
                $row = $chk ? $chk->fetch_assoc() : null;
                if ($row && !$row['is_builtin']) {
                    $conn->query("DELETE FROM nm_oid_configs WHERE id={$id}");
                    echo json_encode(['ok'=>true]);
                } else {
                    echo json_encode(['ok'=>false,'err'=>'Cannot delete built-in template OIDs']);
                }
            } else {
                echo json_encode(['ok'=>false,'err'=>'Invalid ID']);
            }
            break;
        // ── Test SNMP connectivity ─────────────────────────────────────────────
        case 'test_snmp':
            $ip   = preg_replace('/[^0-9a-fA-F.:]/', '', $_GET['ip']   ?? '');
            $comm = preg_replace('/[^a-zA-Z0-9_\-@#!.]/', '', $_GET['community'] ?? 'public');
            $ver  = in_array($_GET['version'] ?? '', ['v1','v2c']) ? ltrim($_GET['version'],'v') : '2c';
            if (!$ip) { echo json_encode(['ok'=>false,'err'=>'No IP']); break; }
            $out = shell_exec("/usr/bin/snmpget -v{$ver} -c {$comm} -Oqv -t 3 -r 1 {$ip} .1.3.6.1.2.1.1.5.0 2>&1");
            $name = trim($out ?? '');
            if ($name && !str_contains($name,'No Such') && !str_contains($name,'Timeout') && !str_contains($name,'Error')) {
                echo json_encode(['ok'=>true,'sysName'=>trim($name,'"')]);
            } else {
                echo json_encode(['ok'=>false,'err'=>$name ?: 'No response']);
            }
            break;

        // ── Get NM global settings ─────────────────────────────────────────────
        case 'get_nm_settings':
            include_once('connection.php');
            $res  = $conn->query("SELECT setting_key, setting_val FROM nm_settings ORDER BY setting_key");
            $data = [];
            if ($res) while ($r=$res->fetch_assoc()) $data[$r['setting_key']] = $r['setting_val'];
            echo json_encode(['settings'=>$data]);
            break;

        // ── Save NM global settings ────────────────────────────────────────────
        case 'save_nm_settings':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $allowed = ['poll_interval_health','poll_interval_ifaces','retention_days',
                        'discovery_enabled','discovery_schedule','discovery_subnets','discovery_communities',
                        'snmp_timeout','snmp_retries','ping_fail_threshold','snmp_stale_minutes'];
            $saved = 0;
            foreach ($allowed as $key) {
                if (!array_key_exists($key, $body)) continue;
                $val = substr(trim((string)$body[$key]), 0, 500);
                $st = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=?");
                $st->bind_param('sss', $key, $val, $val);
                $st->execute();
                $saved++;
            }
            echo json_encode(['ok'=>true,'saved'=>$saved]);
            break;

        // ── Add node directly (no LibreNMS required) ───────────────────────────
        case 'add_node_direct':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $dn   = substr(trim($body['display_name'] ?? ''), 0, 100);
            $ip   = substr(trim($body['ip_address']   ?? ''), 0, 45);
            $comm = substr(trim($body['snmp_community']?? ''), 0, 100);
            $ver  = in_array($body['snmp_version']??'', ['v1','v2c','v3']) ? $body['snmp_version'] : 'v2c';
            $icon = substr(preg_replace('/[^a-z0-9_]/','',strtolower($body['os_icon']??'generic')), 0, 50);
            $gid  = ($body['group_id']??0) ? (int)$body['group_id'] : null;
            $uid  = (int)($_SESSION['user_id'] ?? 0);
            $mask = substr(trim($body['subnet_mask']??'/24'), 0, 18);
            if (!$dn || !$ip) { echo json_encode(['ok'=>false,'err'=>'Display name and IP are required']); break; }
            $lic = nm_lic_can_add_nodes($conn, 1);
            if (!$lic['ok']) { echo json_encode(['ok'=>false,'err'=>nm_lic_node_block_msg($lic),'license_block'=>true,'limit'=>$lic['limit'],'current'=>$lic['current']]); break; }
            $st = $conn->prepare("INSERT INTO nm_nodes
                (display_name,ip_address,os_icon,snmp_community,snmp_version,subnet_mask,group_id,added_by)
                VALUES(?,?,?,?,?,?,?,?)");
            $st->bind_param('ssssssii', $dn, $ip, $icon, $comm, $ver, $mask, $gid, $uid);
            if ($st->execute()) {
                echo json_encode(['ok'=>true,'node_id'=>$conn->insert_id]);
            } else {
                echo json_encode(['ok'=>false,'err'=>$conn->error]);
            }
            break;

        // ── Edit node fields ───────────────────────────────────────────────────
        case 'edit_node':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body  = json_decode(file_get_contents('php://input'), true) ?? [];
            $nid   = (int)($body['node_id'] ?? 0);
            $dn    = substr(trim($body['display_name']   ?? ''), 0, 100);
            $ip    = substr(trim($body['ip_address']     ?? ''), 0, 45);
            $comm  = substr(trim($body['snmp_community'] ?? ''), 0, 100);
            $ver   = in_array($body['snmp_version']??'', ['v1','v2c','v3']) ? $body['snmp_version'] : 'v2c';
            $icon  = substr(preg_replace('/[^a-z0-9_]/','',strtolower($body['os_icon']??'generic')), 0, 50);
            $mask  = substr(trim($body['subnet_mask']    ?? '/24'), 0, 18);
            $gw    = ($body['gateway_node_id']??0) ? (int)$body['gateway_node_id'] : null;
            $gid   = ($body['group_id']??0) ? (int)$body['group_id'] : null;
            if (!$nid || !$dn) { echo json_encode(['ok'=>false,'err'=>'Missing node_id or display_name']); break; }
            $st = $conn->prepare("UPDATE nm_nodes SET display_name=?,ip_address=?,snmp_community=?,snmp_version=?,os_icon=?,subnet_mask=?,gateway_node_id=?,group_id=? WHERE id=?");
            $st->bind_param('sssssssii', $dn, $ip, $comm, $ver, $icon, $mask, $gw, $gid, $nid);
            $st->execute();
            echo json_encode(['ok'=>true]);
            break;

        // ── Get interfaces from our DB (not LibreNMS) ─────────────────────────
        case 'get_node_ifaces':
            include_once('connection.php');
            $nid = (int)($_GET['node_id'] ?? 0);
            $res = $conn->query("SELECT id,if_name,if_alias,display_name,show_graph,sort_order,if_index,lnms_port_id,if_ip_address,is_dummy
                FROM nm_interfaces WHERE node_id={$nid} ORDER BY is_dummy,sort_order,if_index,id");
            echo json_encode(['ifaces'=> $res ? $res->fetch_all(MYSQLI_ASSOC) : []]);
            break;

        // ── Connections (nm_links): explicit device↔device wiring ──────────────
        case 'links_list':
            include_once('connection.php');
            $rows = $conn->query("
                SELECT l.id,l.a_node_id,l.a_iface_id,l.z_node_id,l.z_iface_id,l.traffic_side,l.label,
                       an.display_name a_node, COALESCE(ai.display_name,ai.if_name) a_if,
                       zn.display_name z_node, COALESCE(zi.display_name,zi.if_name) z_if
                FROM nm_links l
                JOIN nm_nodes an ON an.id=l.a_node_id
                JOIN nm_nodes zn ON zn.id=l.z_node_id
                LEFT JOIN nm_interfaces ai ON ai.id=l.a_iface_id
                LEFT JOIN nm_interfaces zi ON zi.id=l.z_iface_id
                ORDER BY l.id DESC");
            echo json_encode(['links'=> $rows ? $rows->fetch_all(MYSQLI_ASSOC) : []]);
            break;

        case 'link_save':
            include_once('connection.php');
            $b   = json_decode(file_get_contents('php://input'), true) ?? [];
            $id  = (int)($b['id'] ?? 0);
            $a   = (int)($b['a_node_id'] ?? 0);
            $z   = (int)($b['z_node_id'] ?? 0);
            $ai  = ((int)($b['a_iface_id'] ?? 0)) ?: null;
            $zi  = ((int)($b['z_iface_id'] ?? 0)) ?: null;
            $ts  = in_array($b['traffic_side'] ?? 'z', ['a','z'], true) ? $b['traffic_side'] : 'z';
            $lbl = substr(trim($b['label'] ?? ''), 0, 100) ?: null;
            if (!$a || !$z || $a === $z) { echo json_encode(['ok'=>false,'err'=>'Pick two different devices']); break; }
            if ($id) {
                $st = $conn->prepare("UPDATE nm_links SET a_node_id=?,a_iface_id=?,z_node_id=?,z_iface_id=?,traffic_side=?,label=? WHERE id=?");
                $st->bind_param('iiiissi', $a,$ai,$z,$zi,$ts,$lbl,$id);
            } else {
                $uid = ((int)($_SESSION['UID'] ?? 0)) ?: null;
                $st = $conn->prepare("INSERT INTO nm_links(a_node_id,a_iface_id,z_node_id,z_iface_id,traffic_side,label,created_by) VALUES(?,?,?,?,?,?,?)");
                $st->bind_param('iiiissi', $a,$ai,$z,$zi,$ts,$lbl,$uid);
            }
            $st->execute();
            echo json_encode(['ok'=>true,'id'=> $id ?: $conn->insert_id]);
            break;

        case 'link_delete':
            include_once('connection.php');
            $b  = json_decode(file_get_contents('php://input'), true) ?? [];
            $id = (int)($b['id'] ?? 0);
            if ($id) $conn->query("DELETE FROM nm_links WHERE id={$id}");
            echo json_encode(['ok'=>true]);
            break;

        case 'iface_add_dummy':
            include_once('connection.php');
            $b    = json_decode(file_get_contents('php://input'), true) ?? [];
            $nid  = (int)($b['node_id'] ?? 0);
            $name = substr(trim($b['name'] ?? ''), 0, 100);
            if (!$nid || $name === '') { echo json_encode(['ok'=>false,'err'=>'Node and interface name required']); break; }
            $st = $conn->prepare("INSERT INTO nm_interfaces(node_id,if_name,display_name,is_dummy,show_graph,sort_order) VALUES(?,?,?,1,0,999)");
            $st->bind_param('iss', $nid, $name, $name);
            $st->execute();
            echo json_encode(['ok'=>true,'id'=>$conn->insert_id]);
            break;

        case 'iface_delete_dummy':
            include_once('connection.php');
            $b  = json_decode(file_get_contents('php://input'), true) ?? [];
            $id = (int)($b['id'] ?? 0);
            if ($id) $conn->query("DELETE FROM nm_interfaces WHERE id={$id} AND is_dummy=1");
            echo json_encode(['ok'=>true]);
            break;

        // ── Auto-connection suppression (nm_link_hidden) ───────────────────────
        // Auto-discovered (gateway/subnet) links are computed live by the map. To
        // "remove" one we store the node pair here; the map skips suppressed pairs.
        case 'links_hidden':
            include_once('connection.php');
            $rows = $conn->query("
                SELECT h.a_node_id, h.z_node_id,
                       an.display_name a_node, zn.display_name z_node
                FROM nm_link_hidden h
                JOIN nm_nodes an ON an.id=h.a_node_id
                JOIN nm_nodes zn ON zn.id=h.z_node_id
                ORDER BY h.id DESC");
            echo json_encode(['hidden'=> $rows ? $rows->fetch_all(MYSQLI_ASSOC) : []]);
            break;

        case 'link_hide':
            include_once('connection.php');
            $b = json_decode(file_get_contents('php://input'), true) ?? [];
            $a = (int)($b['a_node_id'] ?? 0);
            $z = (int)($b['z_node_id'] ?? 0);
            if (!$a || !$z || $a === $z) { echo json_encode(['ok'=>false,'err'=>'Bad node pair']); break; }
            $lo = min($a,$z); $hi = max($a,$z);
            $uid = ((int)($_SESSION['UID'] ?? 0)) ?: null;
            $st = $conn->prepare("INSERT IGNORE INTO nm_link_hidden(a_node_id,z_node_id,created_by) VALUES(?,?,?)");
            $st->bind_param('iii', $lo, $hi, $uid);
            $st->execute();
            echo json_encode(['ok'=>true]);
            break;

        case 'link_unhide':
            include_once('connection.php');
            $b = json_decode(file_get_contents('php://input'), true) ?? [];
            $a = (int)($b['a_node_id'] ?? 0);
            $z = (int)($b['z_node_id'] ?? 0);
            $lo = min($a,$z); $hi = max($a,$z);
            if ($lo && $hi) $conn->query("DELETE FROM nm_link_hidden WHERE a_node_id={$lo} AND z_node_id={$hi}");
            echo json_encode(['ok'=>true]);
            break;

        // ── Graylog: live connection test (System info) ────────────────────────
        case 'graylog_test':
            include_once('connection.php');
            require_once __DIR__ . '/nm_graylog.php';
            $cfg = nm_graylog_get($conn);
            if (isset($_GET['url']))   $cfg['url']   = trim($_GET['url']);
            if (isset($_GET['token'])) $cfg['token'] = trim($_GET['token']);
            [$code, $json, $err] = nm_graylog_api($cfg, '/api/system');
            if ($err) { echo json_encode(['ok'=>false,'err'=>$err,'code'=>$code]); break; }
            echo json_encode(['ok'=>true,
                'version'   => $json['version']    ?? '?',
                'hostname'  => $json['hostname']    ?? '',
                'lifecycle' => $json['lifecycle']   ?? '',
                'cluster'   => $json['cluster_id']  ?? '']);
            break;

        // ── n8n: save outbound config (base url + api key) ─────────────────────
        case 'n8n_save':
            include_once('connection.php');
            require_once __DIR__ . '/nm_n8n.php';
            $b = json_decode(file_get_contents('php://input'), true) ?? [];
            nm_n8n_set($conn, 'n8n_base_url', rtrim(trim((string)($b['base_url'] ?? '')), '/'));
            nm_n8n_set($conn, 'n8n_api_key',  trim((string)($b['api_key'] ?? '')));
            nm_n8n_set($conn, 'n8n_portal_base', rtrim(trim((string)($b['portal_base'] ?? '')), '/'));
            echo json_encode(['ok'=>true]);
            break;

        // ── n8n: generate / rotate the inbound auth token ──────────────────────
        case 'n8n_gen_token':
            include_once('connection.php');
            require_once __DIR__ . '/nm_n8n.php';
            $tok = nm_n8n_new_token();
            nm_n8n_set($conn, 'n8n_inbound_token', $tok);
            echo json_encode(['ok'=>true,'token'=>$tok]);
            break;

        // ── AI Gateway: the vkey + connection key from the NEURU Portal (metered AI Flows) ──
        case 'ai_gateway_save':
            include_once('connection.php');
            $b = json_decode(file_get_contents('php://input'), true) ?? [];
            $set = function($k,$v) use ($conn){
                $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=?");
                $st->bind_param('sss',$k,$v,$v); $st->execute(); $st->close();
            };
            $set('ai_gateway_vkey', trim((string)($b['vkey'] ?? '')));
            $set('ai_conn_key',     trim((string)($b['conn_key'] ?? '')));
            $set('ai_public_base',  rtrim(trim((string)($b['public_base'] ?? '')), '/'));
            echo json_encode(['ok'=>true]);
            break;

        // ── WireGuard interconnect (NAT traversal for hosted AI Flows) ─────────
        case 'wg_status': case 'wg_enroll': case 'wg_disable': {
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php'); require_once __DIR__ . '/access_control.php';
            if (empty($_SESSION['username']) || !checkAccess($conn,'net_mon')) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'unauthorized']); break; }
            require_once __DIR__ . '/nm_wgconn.php';
            if ($_GET['api']==='wg_status') { echo json_encode(['ok'=>true,'state'=>nm_wgconn_state($conn)]); break; }
            if (function_exists('session_write_close')) @session_write_close();   // Portal round-trip ahead
            echo json_encode($_GET['api']==='wg_enroll' ? nm_wgconn_enroll($conn) : nm_wgconn_disable($conn));
            break;
        }

        // ── Flows Sync: pull the customer's subscribed hosted flows from the Portal ──
        case 'flows_sync': {
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php'); require_once __DIR__ . '/access_control.php';
            if (empty($_SESSION['username']) || !checkAccess($conn,'net_mon')) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'unauthorized']); break; }
            require_once __DIR__ . '/nm_n8n.php';
            if (function_exists('session_write_close')) @session_write_close();   // Portal round-trip ahead
            echo json_encode(nm_n8n_flows_sync($conn));
            break;
        }

        // ── n8n webhooks CRUD ──────────────────────────────────────────────────
        case 'webhook_list':
            include_once('connection.php');
            require_once __DIR__ . '/nm_n8n.php';
            echo json_encode(['webhooks'=>nm_n8n_webhooks($conn)]);
            break;

        case 'webhook_save':
            include_once('connection.php');
            $b    = json_decode(file_get_contents('php://input'), true) ?? [];
            $id   = (int)($b['id'] ?? 0);
            $name = substr(trim($b['name'] ?? ''), 0, 120);
            $slug = substr(preg_replace('/[^a-z0-9_\-]/','', strtolower($b['slug'] ?? '')), 0, 80);
            $url  = substr(trim($b['url'] ?? ''), 0, 500);
            $meth = (strtoupper($b['method'] ?? 'POST') === 'GET') ? 'GET' : 'POST';
            $desc = substr(trim($b['description'] ?? ''), 0, 300) ?: null;
            $en   = !empty($b['enabled']) ? 1 : 0;
            if ($name === '' || $slug === '' || $url === '') { echo json_encode(['ok'=>false,'err'=>'Name, slug and URL are required']); break; }
            // If not editing by id, but the slug already exists (e.g. a module auto-registered a
            // disabled placeholder like 'deception-analyst'), UPSERT that row instead of failing on
            // the unique slug. This is why adding/editing a pre-listed webhook always works now.
            if (!$id && $slug !== '') {
                $ex = $conn->prepare("SELECT id FROM nm_n8n_webhooks WHERE slug=? LIMIT 1");
                $ex->bind_param('s', $slug); $ex->execute();
                $exRow = $ex->get_result()->fetch_assoc(); $ex->close();
                if ($exRow) $id = (int)$exRow['id'];
            }
            if ($id) {
                $st = $conn->prepare("UPDATE nm_n8n_webhooks SET name=?,slug=?,url=?,method=?,description=?,enabled=? WHERE id=?");
                $st->bind_param('sssssii', $name,$slug,$url,$meth,$desc,$en,$id);
            } else {
                $uid = ((int)($_SESSION['UID'] ?? 0)) ?: null;
                $st = $conn->prepare("INSERT INTO nm_n8n_webhooks(name,slug,url,method,description,enabled,created_by) VALUES(?,?,?,?,?,?,?)");
                $st->bind_param('sssssii', $name,$slug,$url,$meth,$desc,$en,$uid);
            }
            if (!$st->execute()) { echo json_encode(['ok'=>false,'err'=>('Could not save: '.$conn->error)]); break; }
            echo json_encode(['ok'=>true,'id'=>$id ?: $conn->insert_id]);
            break;

        case 'webhook_delete':
            include_once('connection.php');
            $b  = json_decode(file_get_contents('php://input'), true) ?? [];
            $id = (int)($b['id'] ?? 0);
            if ($id) $conn->query("DELETE FROM nm_n8n_webhooks WHERE id={$id}");
            echo json_encode(['ok'=>true]);
            break;

        // ── Portainer: live connection test ────────────────────────────────────
        case 'portainer_test':
            include_once('connection.php');
            require_once __DIR__ . '/nm_portainer.php';
            $cfg = nm_portainer_cfg($conn);
            if (isset($_GET['url']))    $cfg['url'] = rtrim(trim($_GET['url']), '/');
            if (!empty($_GET['key']))   $cfg['key'] = trim($_GET['key']);   // test the just-typed key (plaintext)
            if (isset($_GET['verify'])) $cfg['verify'] = $_GET['verify'] !== '0';
            $p = nm_portainer_ping($cfg);
            if (!$p['ok']) { echo json_encode(['ok'=>false,'err'=>$p['error'],'code'=>$p['status']]); break; }
            $e = nm_portainer_endpoints($cfg);
            $envs = $e['ok'] ? nm_portainer_norm_endpoints($e['data']) : [];
            echo json_encode(['ok'=>true,'version'=>$p['data']['version'] ?? '?','env_count'=>count($envs)]);
            break;

        // ── Smokeping: save config ─────────────────────────────────────────────
        case 'smokeping_save':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $sp_vals = [
                'smokeping_url'          => rtrim(trim($_POST['smokeping_url'] ?? ''), '/'),
                'smokeping_enabled'      => (!empty($_POST['smokeping_enabled']) && $_POST['smokeping_enabled']!=='0') ? '1' : '0',
                'smokeping_host_ip'      => trim($_POST['smokeping_host_ip'] ?? ''),
                'smokeping_container'    => trim($_POST['smokeping_container'] ?? '') ?: 'smokeping',
                'smokeping_targets_path' => trim($_POST['smokeping_targets_path'] ?? '') ?: '/config/Targets',
                'smokeping_data_path'    => trim($_POST['smokeping_data_path'] ?? '') ?: '/data',
                'smokeping_manage_url'   => trim($_POST['smokeping_manage_url'] ?? ''),
                'smokeping_reload_cmd'   => trim($_POST['smokeping_reload_cmd'] ?? ''),
            ];
            // Latency-alert settings
            $sp_vals['smokeping_alerts_enabled'] = (!empty($_POST['smokeping_alerts_enabled']) && $_POST['smokeping_alerts_enabled']!=='0') ? '1' : '0';
            $sp_vals['smokeping_alert_sustain']  = (string)max(1, min(10, (int)($_POST['smokeping_alert_sustain'] ?? 2)));
            $sp_vals['smokeping_alert_url']      = trim($_POST['smokeping_alert_url'] ?? '');
            foreach ($sp_vals as $k=>$v) {
                $st = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=?");
                $st->bind_param('sss', $k, $v, $v); $st->execute();
            }
            // Global thresholds (node_id=0) — adjustable alert margins
            require_once __DIR__ . '/nm_smokeping.php';
            nm_sp_threshold_save($conn, 0, [
                'rtt_warn'=>$_POST['rtt_warn'] ?? '', 'rtt_crit'=>$_POST['rtt_crit'] ?? '',
                'loss_warn'=>$_POST['loss_warn'] ?? '', 'loss_crit'=>$_POST['loss_crit'] ?? '',
            ]);
            echo json_encode(['ok'=>true]);
            break;

        // ── Smokeping: reachability test (server-side; avoids browser CORS) ─────
        case 'smokeping_test':
            $sp_url = rtrim(trim($_GET['url'] ?? ''), '/');
            if ($sp_url === '') { echo json_encode(['ok'=>false,'err'=>'No URL']); break; }
            $ch = curl_init($sp_url . '/');
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_FOLLOWLOCATION=>true,
                CURLOPT_TIMEOUT=>8, CURLOPT_CONNECTTIMEOUT=>5, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>false]);
            $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $eff = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL); curl_close($ch);
            $isSmoke = ($body !== false && stripos((string)$body, 'smokeping') !== false);
            if ($code >= 200 && $code < 400) echo json_encode(['ok'=>true,'code'=>$code,'smokeping'=>$isSmoke,'url'=>$eff]);
            else echo json_encode(['ok'=>false,'err'=>($code?"HTTP {$code}":'Unreachable'),'code'=>$code]);
            break;

        // ── Pi-hole: list configured servers ──────────────────────────────────
        case 'pihole_list':
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            require_once __DIR__ . '/nm_pihole.php';
            echo json_encode(['ok'=>true,'servers'=>nm_ph_servers($conn)]);
            break;

        // ── Pi-hole: add / update one server (password encrypted, blank=keep) ──
        case 'pihole_server_save':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            require_once __DIR__ . '/nm_pihole.php';
            $r = nm_ph_server_save($conn, [
                'id'       => (int)($_POST['id'] ?? 0),
                'name'     => $_POST['name'] ?? '',
                'url'      => $_POST['url'] ?? '',
                'password' => $_POST['password'] ?? '',
                'verify'   => !empty($_POST['verify_tls']) && $_POST['verify_tls']!=='0',
                'enabled'  => !empty($_POST['enabled']) && $_POST['enabled']!=='0',
            ]);
            echo json_encode($r);
            break;

        // ── Pi-hole: delete a server ───────────────────────────────────────────
        case 'pihole_server_delete':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            require_once __DIR__ . '/nm_pihole.php';
            nm_ph_server_delete($conn, (int)($_POST['id'] ?? 0));
            echo json_encode(['ok'=>true]);
            break;

        // ── Pi-hole: auth + version probe for one server ───────────────────────
        case 'pihole_test':
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            require_once __DIR__ . '/nm_pihole.php';
            $pt = nm_ph_test($conn, (int)($_GET['id'] ?? 0));
            echo json_encode($pt['ok'] ? ['ok'=>true,'version'=>$pt['version'] ?? null] : ['ok'=>false,'err'=>$pt['error'] ?? 'failed']);
            break;

        // ── NetFlow collector: save settings ───────────────────────────────────
        case 'netflow_save':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $nf_set = function($k,$v) use ($conn){
                $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=?");
                $st->bind_param('sss',$k,$v,$v); $st->execute(); $st->close();
            };
            $nf_set('netflow_enabled',        (!empty($_POST['netflow_enabled']) && $_POST['netflow_enabled']!=='0') ? '1':'0');
            $nf_set('netflow_port',           (string)max(1, min(65535, (int)($_POST['netflow_port'] ?? 2055))));
            $nf_set('netflow_retention_days', (string)max(1, min(90, (int)($_POST['netflow_retention_days'] ?? 7))));
            $nf_set('netflow_sampling',       (string)max(1, (int)($_POST['netflow_sampling'] ?? 1)));
            $nf_set('netflow_topn',           (string)max(50, min(2000, (int)($_POST['netflow_topn'] ?? 300))));
            $nf_set('netflow_baseline_mult',  (string)max(2, (int)($_POST['netflow_baseline_mult'] ?? 4)));
            $nf_set('netflow_alert_url',      trim($_POST['netflow_alert_url'] ?? ''));
            echo json_encode(['ok'=>true,'note'=>'Restart the NetFlow collector if you changed the port.']);
            break;

        // ── NetFlow collector: live status from the daemon's stat counters ─────
        case 'netflow_status':
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            require_once __DIR__ . '/nm_netflow.php';
            echo json_encode(['ok'=>true,'status'=>nm_nf_status($conn),'settings'=>nm_nf_settings($conn)]);
            break;

        // ── SMTP (email delivery — any provider) ───────────────────────────────
        case 'smtp_save':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            require_once __DIR__ . '/nm_secrets.php';
            $sm_set = function($k,$v) use ($conn){ $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=?");
                $st->bind_param('sss',$k,$v,$v); $st->execute(); $st->close(); };
            $sm_set('smtp_enabled',  (!empty($_POST['smtp_enabled']) && $_POST['smtp_enabled']!=='0') ? '1':'0');
            $sm_set('smtp_host',     trim($_POST['smtp_host'] ?? ''));
            $sm_set('smtp_port',     (string)max(1, min(65535, (int)($_POST['smtp_port'] ?? 587))));
            $sm_set('smtp_secure',   in_array($_POST['smtp_secure'] ?? '', ['tls','ssl','none'], true) ? $_POST['smtp_secure'] : 'tls');
            $sm_set('smtp_user',     trim($_POST['smtp_user'] ?? ''));
            $sm_set('smtp_from',     trim($_POST['smtp_from'] ?? ''));
            $sm_set('smtp_from_name',trim($_POST['smtp_from_name'] ?? '') ?: 'NEURU');
            $sm_pw = (string)($_POST['smtp_pass'] ?? '');
            if ($sm_pw !== '') $sm_set('smtp_pass_enc', nm_secret_encrypt($sm_pw));   // blank = keep
            echo json_encode(['ok'=>true]);
            break;

        // ── SMTP: send a test email ────────────────────────────────────────────
        case 'smtp_test':
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            require_once __DIR__ . '/nm_smtp.php';
            $sm_to = trim($_GET['to'] ?? ($_SESSION['email'] ?? ''));
            if ($sm_to === '') { echo json_encode(['ok'=>false,'err'=>'No recipient — add a "from"/test address']); break; }
            $smErr = null;
            $smOk = nm_smtp_send($conn, $sm_to, 'NEURU SMTP test ✅', "This is a test email from NEURU.\nIf you got this, SMTP delivery works.", $smErr);
            echo json_encode($smOk ? ['ok'=>true,'to'=>$sm_to] : ['ok'=>false,'err'=>$smErr ?: 'send failed']);
            break;

        // ── NEURU syslog server: save settings + log-source selector ───────────
        case 'syslog_save':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $sy = [
                'log_source'             => (($_POST['log_source'] ?? 'syslog') === 'graylog') ? 'graylog' : 'syslog',
                'syslog_port'            => (string)max(1, min(65535, (int)($_POST['syslog_port'] ?? 514))),
                'syslog_retention_days'  => (string)max(1, min(3650, (int)($_POST['syslog_retention_days'] ?? 30))),
                'syslog_tcp_enabled'     => (!empty($_POST['syslog_tcp_enabled']) && $_POST['syslog_tcp_enabled']!=='0') ? '1' : '0',
            ];
            foreach ($sy as $k=>$v) {
                $st = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=?");
                $st->bind_param('sss', $k, $v, $v); $st->execute();
            }
            echo json_encode(['ok'=>true,'note'=>'Restart the syslog daemon if you changed the port.']);
            break;

        // ── NEURU syslog server: live status (is it receiving?) ────────────────
        case 'syslog_status':
            include_once('connection.php');
            if ($conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows === 0) { echo json_encode(['ok'=>true,'table'=>false]); break; }
            // nm_syslog can hold tens of MILLIONS of rows — a bare COUNT(*)/COUNT(DISTINCT)
            // full-scans the whole table (~19s on 21M rows) and stalls the config page. Instead:
            //  • total   = approximate row count from table metadata (instant)
            //  • last_at = index-assisted MAX(received_at)   (instant, uses idx_time)
            //  • last5m/sources = only the last-5-min window via idx_time  (scans a tiny slice)
            $total = 0;
            if ($tr = $conn->query("SELECT TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_syslog' LIMIT 1"))
                $total = (int)(($tr->fetch_row()[0]) ?? 0);
            $last_at = null;
            if ($m = $conn->query("SELECT MAX(received_at) FROM nm_syslog")) $last_at = $m->fetch_row()[0];
            $w = $conn->query("SELECT COUNT(*) last5m, COUNT(DISTINCT host_ip) sources
                               FROM nm_syslog WHERE received_at >= (UTC_TIMESTAMP() - INTERVAL 5 MINUTE)")->fetch_assoc();
            echo json_encode(['ok'=>true,'table'=>true,'total'=>$total,
                'last5m'=>(int)($w['last5m']??0),'sources'=>(int)($w['sources']??0),'last_at'=>$last_at ?? 0]);
            break;

        // ── SSH credentials (for self-heal apply) ──────────────────────────────
        // Secrets are AES-256-GCM encrypted at rest (nm_secrets.php). The secret is
        // NEVER returned to the browser — only whether one is set.
        case 'ssh_cred_list':
            include_once('connection.php');
            $r = $conn->query("SELECT id,name,username,auth_type,port,is_default,
                                      (secret_enc IS NOT NULL AND secret_enc<>'') has_secret
                               FROM nm_ssh_credentials ORDER BY is_default DESC, name");
            echo json_encode(['creds'=> $r ? $r->fetch_all(MYSQLI_ASSOC) : []]);
            break;

        case 'ssh_cred_save':
            include_once('connection.php');
            $b   = json_decode(file_get_contents('php://input'), true) ?? [];
            $id  = (int)($b['id'] ?? 0);
            $nm  = substr(trim($b['name'] ?? ''), 0, 80);
            $usr = substr(trim($b['username'] ?? ''), 0, 80);
            $at  = (($b['auth_type'] ?? 'password') === 'key') ? 'key' : 'password';
            $port= (int)($b['port'] ?? 22) ?: 22;
            $def = !empty($b['is_default']) ? 1 : 0;
            $sec = (string)($b['secret'] ?? '');
            if ($nm === '' || $usr === '') { echo json_encode(['ok'=>false,'err'=>'Name and username required']); break; }
            $enc = $sec !== '' ? nm_secret_encrypt($sec) : null;
            if ($id) {
                if ($enc !== null) {
                    $st = $conn->prepare("UPDATE nm_ssh_credentials SET name=?,username=?,auth_type=?,port=?,is_default=?,secret_enc=? WHERE id=?");
                    $st->bind_param('sssiisi', $nm,$usr,$at,$port,$def,$enc,$id);
                } else {  // keep existing secret when none re-entered
                    $st = $conn->prepare("UPDATE nm_ssh_credentials SET name=?,username=?,auth_type=?,port=?,is_default=? WHERE id=?");
                    $st->bind_param('sssiii', $nm,$usr,$at,$port,$def,$id);
                }
                $st->execute();
            } else {
                $uid = ((int)($_SESSION['UID'] ?? 0)) ?: null;
                $st = $conn->prepare("INSERT INTO nm_ssh_credentials(name,username,auth_type,port,is_default,secret_enc,created_by) VALUES(?,?,?,?,?,?,?)");
                $st->bind_param('sssiisi', $nm,$usr,$at,$port,$def,$enc,$uid);
                $st->execute(); $id = $conn->insert_id;
            }
            if ($def) $conn->query("UPDATE nm_ssh_credentials SET is_default=0 WHERE id<>{$id}");   // only one default
            echo json_encode(['ok'=>true,'id'=>$id]);
            break;

        case 'ssh_cred_delete':
            include_once('connection.php');
            $b  = json_decode(file_get_contents('php://input'), true) ?? [];
            $id = (int)($b['id'] ?? 0);
            if ($id) {
                $conn->query("UPDATE nm_nodes SET ssh_cred_id=NULL WHERE ssh_cred_id={$id}");
                $conn->query("DELETE FROM nm_ssh_credentials WHERE id={$id}");
            }
            echo json_encode(['ok'=>true]);
            break;

        case 'node_cred_map':
            include_once('connection.php');
            $r = $conn->query("SELECT id, display_name, ip_address, ssh_cred_id FROM nm_nodes ORDER BY display_name");
            echo json_encode(['nodes'=> $r ? $r->fetch_all(MYSQLI_ASSOC) : []]);
            break;

        case 'ssh_cred_assign':
            include_once('connection.php');
            $b   = json_decode(file_get_contents('php://input'), true) ?? [];
            $nid = (int)($b['node_id'] ?? 0);
            $cid = ((int)($b['cred_id'] ?? 0)) ?: null;
            if ($nid) {
                $st = $conn->prepare("UPDATE nm_nodes SET ssh_cred_id=? WHERE id=?");
                $st->bind_param('ii', $cid, $nid); $st->execute();
            }
            echo json_encode(['ok'=>true]);
            break;

        // ── Docker host → SSH credential assignment (Containers self-heal) ──────
        case 'host_cred_map':
            include_once('connection.php');
            require_once __DIR__ . '/nm_portainer.php';
            $cfg = nm_portainer_cfg($conn); $hosts = [];
            if (nm_portainer_configured($cfg)) {
                $e = nm_portainer_endpoints($cfg);
                foreach (($e['ok'] ? (array)$e['data'] : []) as $ep) {
                    $eid = (int)($ep['Id'] ?? 0); $name = $ep['Name'] ?? '';
                    $ip = nm_portainer_host_ip($cfg, $eid, $name);
                    if ($ip !== '' && !isset($hosts[$ip])) $hosts[$ip] = ['host'=>$ip,'name'=>$name,'cred_id'=>0];
                }
            }
            if ($conn->query("SHOW TABLES LIKE 'nm_ssh_host_creds'")->num_rows > 0) {
                $r = $conn->query("SELECT host,cred_id FROM nm_ssh_host_creds");
                while ($r && $x = $r->fetch_assoc()) if (isset($hosts[$x['host']])) $hosts[$x['host']]['cred_id'] = (int)$x['cred_id'];
            }
            echo json_encode(['hosts'=>array_values($hosts), 'portainer'=>nm_portainer_configured($cfg)]);
            break;

        case 'host_cred_assign':
            include_once('connection.php');
            $b = json_decode(file_get_contents('php://input'), true) ?? [];
            $host = substr(trim($b['host'] ?? ''), 0, 64);
            $cid  = (int)($b['cred_id'] ?? 0);
            if ($host !== '') {
                if ($cid) { $st=$conn->prepare("INSERT INTO nm_ssh_host_creds(host,cred_id) VALUES(?,?) ON DUPLICATE KEY UPDATE cred_id=VALUES(cred_id)"); $st->bind_param('si',$host,$cid); $st->execute(); }
                else      { $st=$conn->prepare("DELETE FROM nm_ssh_host_creds WHERE host=?"); $st->bind_param('s',$host); $st->execute(); }
            }
            echo json_encode(['ok'=>true]);
            break;

        // ── n8n: test-fire a webhook by slug (proxied server-side) ─────────────
        case 'webhook_test':
            include_once('connection.php');
            require_once __DIR__ . '/nm_n8n.php';
            $slug = preg_replace('/[^a-z0-9_\-]/','', strtolower($_GET['slug'] ?? ''));
            // Self-identifying test that NEVER crashes a flow expecting callback URLs / a problem
            // (e.g. rc-suggest would throw "URL parameter cannot be empty" on a bare body). We send
            // a `test` flag + harmless placeholder fields + valid (id=0) callback URLs so the flow
            // can short-circuit on `event==='test'` and, even if it doesn't, no URL field is empty.
            if (function_exists("session_write_close")) @session_write_close(); // release lock before n8n round-trip
            $base = ((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http').'://'.($_SERVER['HTTP_HOST']?:'localhost');
            // 12s probe (not 25s): we only need to know the webhook is REACHABLE. Callback-style flows
            // (rc-exec, rc-suggest, self-heal-apply, container-*-exec) never reply synchronously — they
            // accept the request, run work, and POST results back — so a timeout here means "reached +
            // running async", NOT "failed". Only a connect/resolve error is a true unreachable.
            [$code,$resp,$err] = nm_n8n_call($conn, $slug, [
                'event'=>'test', 'test'=>true,
                'message'=>'NEURU webhook connectivity test — no real session, please ignore / respond 200',
                'problem'=>'(connectivity test)', 'device_kind'=>'test', 'transport'=>'test',
                'session_id'=>'test', 'rc_id'=>0,
                'log_url'      => $base.'/nm_router_api.php?ep=rc_log&id=0',
                'result_url'   => $base.'/nm_router_api.php?ep=rc_result&id=0',
                'proposal_url' => $base.'/nm_router_api.php?ep=rc_proposal&id=0',
                'continue_url' => $base.'/nm_router_api.php?ep=rc_continue&id=0',
            ], 12);
            $sync     = ($code >= 200 && $code < 400);                       // flow replied synchronously
            $timedOut = ($err && preg_match('/tim(e|ed)\s?out|timed out/i', (string)$err));
            echo json_encode(['ok'=>$sync, 'reachable'=>($sync || $timedOut), 'async'=>(!$sync && $timedOut),
                'code'=>$code, 'err'=>$err, 'resp'=>is_string($resp)?substr($resp,0,400):$resp]);
            break;

        // ── Discover interfaces via SNMP for a node ────────────────────────────
        case 'discover_ifaces':
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $nid = (int)($_GET['node_id'] ?? 0);
            if (!$nid) { echo json_encode(['ok'=>false,'err'=>'No node_id']); break; }
            $nr = $conn->query("SELECT ip_address,snmp_community,snmp_version FROM nm_nodes WHERE id={$nid} LIMIT 1");
            $node = $nr ? $nr->fetch_assoc() : null;
            if (!$node || !$node['ip_address'] || !$node['snmp_community']) {
                echo json_encode(['ok'=>false,'err'=>'Node has no IP or SNMP community configured']); break;
            }
            $ip   = preg_replace('/[^0-9a-fA-F.:]/','',$node['ip_address']);
            $comm = preg_replace('/[^a-zA-Z0-9_\-@#!.]/','',$node['snmp_community']);
            $ver  = ($node['snmp_version']==='v1') ? '1' : '2c';
            $base = '1.3.6.1.2.1.2.2.1.2';
            $out  = shell_exec("/usr/bin/snmpwalk -v{$ver} -c {$comm} -Oqn -t 3 -r 1 {$ip} .{$base} 2>&1");
            $found = []; $added = 0; $updated = 0;
            foreach (explode("\n", trim($out ?? '')) as $line) {
                $line = trim($line); if (!$line) continue;
                $parts = explode(' ', $line, 2); if (count($parts)!==2) continue;
                $oid = ltrim($parts[0],'.'); $val = trim($parts[1],'"');
                if (!str_starts_with($oid, $base)) continue;
                $suffix = ltrim(substr($oid, strlen($base)), '.');
                if (!is_numeric($suffix)) continue;
                $found[(int)$suffix] = substr($val, 0, 100);
            }
            $exr = $conn->query("SELECT id,if_name,if_index FROM nm_interfaces WHERE node_id={$nid}");
            $ex_by_idx  = []; $ex_by_name = [];
            while ($r=$exr->fetch_assoc()) {
                if ($r['if_index']!==null) $ex_by_idx[(int)$r['if_index']] = (int)$r['id'];
                $ex_by_name[$r['if_name']] = (int)$r['id'];
            }
            foreach ($found as $idx => $name) {
                if (isset($ex_by_idx[$idx])) continue;
                if (isset($ex_by_name[$name])) {
                    $conn->query("UPDATE nm_interfaces SET if_index={$idx} WHERE id={$ex_by_name[$name]}");
                    $updated++;
                } else {
                    $st = $conn->prepare("INSERT INTO nm_interfaces(node_id,if_name,display_name,if_index,show_graph,sort_order) VALUES(?,?,?,?,1,?)");
                    $st->bind_param('issii', $nid, $name, $name, $idx, $idx);
                    $st->execute(); $added++;
                }
            }
            // Populate if_ip_address from ipAddrTable (.1.3.6.1.2.1.4.20.1.2 = ifIndex column)
            $ip_out = shell_exec("/usr/bin/snmpwalk -v{$ver} -c {$comm} -Oqn -t 3 -r 1 {$ip} .1.3.6.1.2.1.4.20.1.2 2>&1");
            foreach (explode("\n", trim($ip_out ?? '')) as $line) {
                $line = trim($line); if (!$line) continue;
                $lp = explode(' ', $line, 2); if (count($lp)!==2) continue;
                $oid = ltrim($lp[0],'.'); $val = trim($lp[1],'"');
                $pfx = '1.3.6.1.2.1.4.20.1.2.';
                if (!str_starts_with($oid, $pfx)) continue;
                $entry_ip = substr($oid, strlen($pfx));
                $ifidx    = (int)$val;
                $safe_ip  = filter_var($entry_ip, FILTER_VALIDATE_IP) ? $entry_ip : null;
                if ($safe_ip && $ifidx) {
                    $esc = $conn->real_escape_string($safe_ip);
                    $conn->query("UPDATE nm_interfaces SET if_ip_address='{$esc}' WHERE node_id={$nid} AND if_index={$ifidx}");
                }
            }
            echo json_encode(['ok'=>true,'found'=>count($found),'added'=>$added,'updated'=>$updated]);
            break;

        // ── Update one interface (display_name, show_graph) ────────────────────
        case 'update_iface':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $id   = (int)($body['id'] ?? 0);
            if (!$id) { echo json_encode(['ok'=>false,'err'=>'Missing id']); break; }
            $dname = isset($body['display_name']) ? substr(trim($body['display_name']),0,100) : null;
            $show  = isset($body['show_graph']) ? ($body['show_graph'] ? 1 : 0) : null;
            $ifip  = isset($body['if_ip_address'])
                ? (filter_var(trim($body['if_ip_address']), FILTER_VALIDATE_IP) ? trim($body['if_ip_address']) : '')
                : null;
            $sets = []; $types = ''; $vals = [];
            if ($dname !== null) { $sets[] = 'display_name=?'; $types .= 's'; $vals[] = $dname; }
            if ($show  !== null) { $sets[] = 'show_graph=?';   $types .= 'i'; $vals[] = $show; }
            if ($ifip  !== null) { $sets[] = 'if_ip_address=?';$types .= 's'; $vals[] = ($ifip === '' ? null : $ifip); }
            if (!$sets) { echo json_encode(['ok'=>false,'err'=>'Nothing to update']); break; }
            $types .= 'i'; $vals[] = $id;
            $st = $conn->prepare("UPDATE nm_interfaces SET ".implode(',',$sets)." WHERE id=?");
            $st->bind_param($types, ...$vals);
            $st->execute();
            echo json_encode(['ok'=>true]);
            break;

        // ── Delete one interface ───────────────────────────────────────────────
        case 'del_iface':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $id   = (int)($body['id'] ?? 0);
            if ($id) { $conn->query("DELETE FROM nm_interfaces WHERE id={$id}"); echo json_encode(['ok'=>true]); }
            else { echo json_encode(['ok'=>false,'err'=>'Missing id']); }
            break;

        // ── Run LAN discovery ─────────────────────────────────────────────────────
        case 'run_discovery':
            if (session_status()===PHP_SESSION_NONE) session_start();
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $py  = VENV_PYTHON;
            $scr = SCRIPTS_DIR . '/nm_discovery.py';
            $out = shell_exec("$py $scr 2>&1");
            echo json_encode(['ok'=>true,'output'=>$out?:('No output')]);
            break;

        // ── Get discovery candidates ──────────────────────────────────────────────
        case 'get_candidates':
            include_once('connection.php');
            $res = $conn->query("SELECT * FROM nm_discovery_candidates
                ORDER BY FIELD(status,'pending','imported','rejected'), discovered_at DESC");
            echo json_encode(['candidates'=> $res ? $res->fetch_all(MYSQLI_ASSOC) : []]);
            break;

        // ── Import one candidate into nm_nodes ────────────────────────────────────
        case 'import_candidate':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $cid  = (int)($body['id'] ?? 0);
            if (!$cid) { echo json_encode(['ok'=>false,'err'=>'Missing id']); break; }
            $cr = $conn->prepare("SELECT * FROM nm_discovery_candidates WHERE id=? LIMIT 1");
            $cr->bind_param('i', $cid); $cr->execute();
            $cand = $cr->get_result()->fetch_assoc();
            if (!$cand) { echo json_encode(['ok'=>false,'err'=>'Candidate not found']); break; }
            // Check if IP already exists in nm_nodes
            $ex = $conn->prepare("SELECT id FROM nm_nodes WHERE ip_address=? LIMIT 1");
            $ex->bind_param('s', $cand['ip_address']); $ex->execute();
            $ex_row = $ex->get_result()->fetch_assoc();
            if ($ex_row) {
                $upd = $conn->prepare("UPDATE nm_discovery_candidates SET status='imported',node_id=? WHERE id=?");
                $upd->bind_param('ii', $ex_row['id'], $cid); $upd->execute();
                echo json_encode(['ok'=>true,'node_id'=>$ex_row['id'],'note'=>'IP already in nodes']);
                break;
            }
            $lic = nm_lic_can_add_nodes($conn, 1);
            if (!$lic['ok']) { echo json_encode(['ok'=>false,'err'=>nm_lic_node_block_msg($lic),'license_block'=>true,'limit'=>$lic['limit'],'current'=>$lic['current']]); break; }
            $dn   = substr($cand['sys_name'] ?: $cand['ip_address'], 0, 100);
            $ip   = $cand['ip_address'];
            $comm = $cand['snmp_community'] ?? '';
            $ver  = $cand['snmp_version']   ?? 'v2c';
            $icon = $cand['os_guess']       ?? 'generic';
            $uid  = (int)($_SESSION['user_id'] ?? 0);
            $st   = $conn->prepare("INSERT INTO nm_nodes (display_name,ip_address,snmp_community,snmp_version,os_icon,added_by) VALUES(?,?,?,?,?,?)");
            $st->bind_param('sssssi', $dn, $ip, $comm, $ver, $icon, $uid);
            if ($st->execute()) {
                $nid = $conn->insert_id;
                $upd = $conn->prepare("UPDATE nm_discovery_candidates SET status='imported',node_id=? WHERE id=?");
                $upd->bind_param('ii', $nid, $cid); $upd->execute();
                echo json_encode(['ok'=>true,'node_id'=>$nid]);
            } else {
                echo json_encode(['ok'=>false,'err'=>$conn->error]);
            }
            break;

        // ── Reject one candidate ──────────────────────────────────────────────────
        case 'reject_candidate':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            $id   = (int)($body['id'] ?? 0);
            if ($id) { $conn->query("UPDATE nm_discovery_candidates SET status='rejected' WHERE id={$id}"); echo json_encode(['ok'=>true]); }
            else { echo json_encode(['ok'=>false,'err'=>'Missing id']); }
            break;

        // ── Clear rejected candidates ─────────────────────────────────────────────
        case 'clear_rejected':
            if ($_SERVER['REQUEST_METHOD']!=='POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); break; }
            if (session_status()===PHP_SESSION_NONE) session_start();
            include_once('connection.php');
            if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); break; }
            $conn->query("DELETE FROM nm_discovery_candidates WHERE status='rejected'");
            echo json_encode(['ok'=>true,'deleted'=>$conn->affected_rows]);
            break;

        default:
            echo json_encode(['err'=>'Unknown endpoint']);
    }
    exit;
}

// ─── Includes & auth ─────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
include('logger.php');
if (!checkAccess($conn,'net_mon')) { header("Location: /denied_access.php?page=net_mon_config"); exit; }

// ─── Auto-create tables ───────────────────────────────────────────────────────
$conn->query("CREATE TABLE IF NOT EXISTS nm_groups(
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    color VARCHAR(20) DEFAULT '#4da3ff',
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$conn->query("CREATE TABLE IF NOT EXISTS nm_nodes(
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_id INT DEFAULT NULL,
    lnms_device_id INT NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    hostname VARCHAR(200),
    location VARCHAR(200),
    os_icon VARCHAR(50) DEFAULT 'generic',
    hw_model VARCHAR(200),
    snmp_community VARCHAR(100) DEFAULT NULL,
    snmp_version VARCHAR(10) DEFAULT NULL,
    sort_order INT DEFAULT 0,
    added_by INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_dev(lnms_device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
// Ensure SNMP columns exist — try/catch because MySQL doesn't support IF NOT EXISTS on ALTER
foreach ([
    "ALTER TABLE nm_nodes ADD COLUMN snmp_community   VARCHAR(100) DEFAULT NULL",
    "ALTER TABLE nm_nodes ADD COLUMN snmp_version     VARCHAR(10)  DEFAULT NULL",
    "ALTER TABLE nm_nodes ADD COLUMN oid_template_id  INT          DEFAULT NULL",
] as $_sql) { try { $conn->query($_sql); } catch(Exception $_e) {} }

// OID template tables
$conn->query("CREATE TABLE IF NOT EXISTS nm_oid_templates(
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    os_type     VARCHAR(50) DEFAULT 'generic',
    description VARCHAR(500) DEFAULT NULL,
    is_builtin  TINYINT(1) DEFAULT 0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_name(name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$conn->query("CREATE TABLE IF NOT EXISTS nm_oid_configs(
    id          INT AUTO_INCREMENT PRIMARY KEY,
    template_id INT DEFAULT NULL,
    node_id     INT DEFAULT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_type VARCHAR(50) DEFAULT 'custom',
    oid         VARCHAR(200) NOT NULL,
    oid_total   VARCHAR(200) DEFAULT NULL,
    unit        VARCHAR(20) DEFAULT '%',
    walk        TINYINT(1) DEFAULT 0,
    scale       DECIMAL(12,6) DEFAULT 1.000000,
    description VARCHAR(300) DEFAULT NULL,
    enabled     TINYINT(1) DEFAULT 1,
    sort_order  INT DEFAULT 0,
    INDEX idx_template(template_id),
    INDEX idx_node(node_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// Seed built-in templates (IGNORE = no-op if already exists)
$conn->query("INSERT IGNORE INTO nm_oid_templates(name,os_type,description,is_builtin) VALUES
    ('Generic / HOST-RESOURCES-MIB','generic','Universal standard MIBs. CPU via hrProcessorLoad, memory+disk via hrStorageTable. Works for MikroTik, Linux, Cisco and most SNMP devices.',1),
    ('MikroTik RouterOS','mikrotik','MikroTik enterprise OIDs for temperature, fan speed, and voltage sensors (mtxrHlTable). Combine with Generic for full metrics.',1),
    ('Linux / NET-SNMP','linux','UCD-SNMP MIB OIDs for Linux servers running net-snmp (snmpd).',1),
    ('Cisco IOS / IOS-XE','cisco','Cisco enterprise OIDs for CPU utilization and memory pools.',1),
    ('Windows Server / HOST-RESOURCES-MIB','windows','For Windows (SNMP Service enabled). CPU, RAM% and per-volume disk are already auto-collected via HOST-RESOURCES-MIB; this template adds the Windows-specific extras: running processes, logged-in users, and total physical RAM.',1)
");
// Seed MikroTik OIDs
$_r = $conn->query("SELECT id FROM nm_oid_templates WHERE os_type='mikrotik' AND is_builtin=1 LIMIT 1");
if ($_r && ($_tid_row = $_r->fetch_assoc())) {
    $_tid = (int)$_tid_row['id'];
    if (!$conn->query("SELECT id FROM nm_oid_configs WHERE template_id={$_tid} LIMIT 1")->num_rows) {
        $conn->query("INSERT IGNORE INTO nm_oid_configs(template_id,metric_name,metric_type,oid,unit,walk,scale,description,sort_order) VALUES
            ({$_tid},'CPU Temp','temperature','.1.3.6.1.4.1.14988.1.1.3.11.0','°C',0,0.1,'mtxrHlCpuTemperature (tenths of °C)',10),
            ({$_tid},'Board Temp','temperature','.1.3.6.1.4.1.14988.1.1.3.10.0','°C',0,0.1,'mtxrHlBoardTemperature (tenths of °C)',20),
            ({$_tid},'Fan Speed','custom','.1.3.6.1.4.1.14988.1.1.3.14.0','RPM',0,1.0,'mtxrHlActiveFan (RPM)',30),
            ({$_tid},'Voltage','custom','.1.3.6.1.4.1.14988.1.1.3.8.0','V',0,0.1,'mtxrHlVoltage (tenths of V)',40)
        ");
    }
}
// Seed Linux OIDs
$_r = $conn->query("SELECT id FROM nm_oid_templates WHERE os_type='linux' AND is_builtin=1 LIMIT 1");
if ($_r && ($_tid_row = $_r->fetch_assoc())) {
    $_tid = (int)$_tid_row['id'];
    if (!$conn->query("SELECT id FROM nm_oid_configs WHERE template_id={$_tid} LIMIT 1")->num_rows) {
        $conn->query("INSERT IGNORE INTO nm_oid_configs(template_id,metric_name,metric_type,oid,unit,walk,scale,description,sort_order) VALUES
            ({$_tid},'CPU User','cpu','.1.3.6.1.4.1.2021.11.9.0','%',0,1.0,'UCD-SNMP ssCpuUser',10),
            ({$_tid},'CPU System','cpu','.1.3.6.1.4.1.2021.11.10.0','%',0,1.0,'UCD-SNMP ssCpuSystem',20),
            ({$_tid},'CPU Idle','cpu','.1.3.6.1.4.1.2021.11.11.0','%',0,1.0,'UCD-SNMP ssCpuIdle',30),
            ({$_tid},'RAM Total kB','memory','.1.3.6.1.4.1.2021.4.5.0','kB',0,1.0,'UCD-SNMP memTotalReal',40),
            ({$_tid},'RAM Free kB','memory','.1.3.6.1.4.1.2021.4.6.0','kB',0,1.0,'UCD-SNMP memAvailReal',50),
            ({$_tid},'Disk Used %','disk','.1.3.6.1.4.1.2021.9.1.9','%',1,1.0,'UCD-SNMP dskPercent walk (all mounts)',60)
        ");
    }
}
// Seed Cisco OIDs
$_r = $conn->query("SELECT id FROM nm_oid_templates WHERE os_type='cisco' AND is_builtin=1 LIMIT 1");
if ($_r && ($_tid_row = $_r->fetch_assoc())) {
    $_tid = (int)$_tid_row['id'];
    if (!$conn->query("SELECT id FROM nm_oid_configs WHERE template_id={$_tid} LIMIT 1")->num_rows) {
        $conn->query("INSERT IGNORE INTO nm_oid_configs(template_id,metric_name,metric_type,oid,oid_total,unit,walk,scale,description,sort_order) VALUES
            ({$_tid},'CPU 5min','cpu','.1.3.6.1.4.1.9.9.109.1.1.1.1.8',NULL,'%',1,1.0,'cpmCPUTotal5minRev walk',10),
            ({$_tid},'Memory Used %','memory','.1.3.6.1.4.1.9.9.48.1.1.1.5','.1.3.6.1.4.1.9.9.48.1.1.1.6','%',0,1.0,'ciscoMemoryPool used/(used+free)',20)
        ");
    }
}
// Seed Windows OIDs (HOST-RESOURCES-MIB extras — CPU/RAM/disk/uptime/interfaces are
// already auto-polled for every SNMP node, so this template only adds the rest).
$_r = $conn->query("SELECT id FROM nm_oid_templates WHERE os_type='windows' AND is_builtin=1 LIMIT 1");
if ($_r && ($_tid_row = $_r->fetch_assoc())) {
    $_tid = (int)$_tid_row['id'];
    if (!$conn->query("SELECT id FROM nm_oid_configs WHERE template_id={$_tid} LIMIT 1")->num_rows) {
        $conn->query("INSERT IGNORE INTO nm_oid_configs(template_id,metric_name,metric_type,oid,unit,walk,scale,description,sort_order) VALUES
            ({$_tid},'Running Processes','custom','.1.3.6.1.2.1.25.1.6.0','proc',0,1.0,'hrSystemProcesses — number of process contexts currently loaded',10),
            ({$_tid},'Logged-in Users','custom','.1.3.6.1.2.1.25.1.5.0','users',0,1.0,'hrSystemNumUsers — user sessions on the host',20),
            ({$_tid},'Physical RAM Total','custom','.1.3.6.1.2.1.25.2.2.0','kB',0,1.0,'hrMemorySize — total installed physical RAM (kB)',30)
        ");
    }
}

$conn->query("CREATE TABLE IF NOT EXISTS nm_interfaces(
    id INT AUTO_INCREMENT PRIMARY KEY,
    node_id INT NOT NULL,
    lnms_port_id INT DEFAULT NULL,
    if_name VARCHAR(100),
    if_alias VARCHAR(200),
    display_name VARCHAR(100),
    show_graph TINYINT(1) DEFAULT 1,
    sort_order INT DEFAULT 0,
    if_index INT DEFAULT NULL,
    if_ip_address VARCHAR(45) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
// Add if_ip_address column for multi-subnet router support (idempotent)
$_col_chk = $conn->query("SELECT COUNT(*) c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_interfaces' AND COLUMN_NAME='if_ip_address'");
if ($_col_chk && (int)$_col_chk->fetch_assoc()['c'] === 0) {
    $conn->query("ALTER TABLE nm_interfaces ADD COLUMN if_ip_address VARCHAR(45) DEFAULT NULL");
}

$conn->query("CREATE TABLE IF NOT EXISTS nm_discovery_candidates(
    id             INT AUTO_INCREMENT PRIMARY KEY,
    ip_address     VARCHAR(45) NOT NULL,
    sys_name       VARCHAR(200) DEFAULT NULL,
    sys_descr      VARCHAR(500) DEFAULT NULL,
    snmp_community VARCHAR(100) DEFAULT NULL,
    snmp_version   VARCHAR(10) DEFAULT NULL,
    os_guess       VARCHAR(50) DEFAULT 'generic',
    subnet         VARCHAR(45) DEFAULT NULL,
    discovered_at  DATETIME NOT NULL,
    status         ENUM('pending','imported','rejected') DEFAULT 'pending',
    node_id        INT DEFAULT NULL,
    UNIQUE KEY uk_ip(ip_address),
    INDEX idx_status(status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// ─── POST handlers ────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD']==='POST') {
    $act = $_POST['action']??'';

    if ($act==='save_lnms') {
        $cfg=['url'=>rtrim(trim($_POST['lnms_url']??''),'/'),
              'token'=>trim($_POST['lnms_token']??''),
              'enabled'=>isset($_POST['lnms_enabled'])];
        nm_lnms_save($conn, $cfg);
        nm_audit($conn, 'config.save_lnms', ['target_type'=>'librenms',
            'details'=>['url'=>$cfg['url'],'enabled'=>$cfg['enabled']]]);
        header('Location: net_mon_config.php?tab=connection&saved=1'); exit;
    }

    if ($act==='save_alloy') {   // Grafana Alloy defaults for the Linux Monitor (per-host source)
        $set = function($k,$v) use ($conn){ $v=$conn->real_escape_string($v);
            $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('{$k}','{$v}') ON DUPLICATE KEY UPDATE setting_val='{$v}'"); };
        $port = (int)($_POST['alloy_port'] ?? 12345); if ($port<1||$port>65535) $port=12345;
        $path = trim($_POST['alloy_path'] ?? '/metrics'); if ($path==='' ) $path='/metrics'; if ($path[0]!=='/') $path='/'.$path;
        $set('alloy_port', (string)$port); $set('alloy_path', substr($path,0,120));
        nm_audit($conn, 'config.save_alloy', ['target_type'=>'alloy']);
        header('Location: net_mon_config.php?tab=integrations&saved=1'); exit;
    }
    if ($act==='save_portainer') {
        $set = function($k,$v) use ($conn){ $v=$conn->real_escape_string($v);
            $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('{$k}','{$v}') ON DUPLICATE KEY UPDATE setting_val='{$v}'"); };
        $set('portainer_url', rtrim(trim($_POST['portainer_url'] ?? ''), '/'));
        $set('portainer_verify_ssl', isset($_POST['portainer_verify_ssl']) ? '1' : '0');
        $set('portainer_host_map', substr(trim($_POST['portainer_host_map'] ?? ''), 0, 4000));
        // Only overwrite the key when a new one is typed (encrypt at rest).
        $newkey = trim($_POST['portainer_api_key'] ?? '');
        if ($newkey !== '') $set('portainer_api_key', nm_secret_encrypt($newkey));
        nm_audit($conn, 'config.save_portainer', ['target_type'=>'portainer']);
        header('Location: net_mon_config.php?tab=containers&saved=1'); exit;
    }

    if ($act==='save_container_settings') {
        $set = function($k,$v) use ($conn){ $v=$conn->real_escape_string($v);
            $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('{$k}','{$v}') ON DUPLICATE KEY UPDATE setting_val='{$v}'"); };
        $set('error_watch_enabled', isset($_POST['error_watch_enabled']) ? '1' : '0');
        $set('container_logs_collect', isset($_POST['container_logs_collect']) ? '1' : '0');
        $set('error_watch_keywords', substr(trim($_POST['error_watch_keywords'] ?? ''), 0, 500));
        $set('error_watch_ignore',   substr(trim($_POST['error_watch_ignore'] ?? ''), 0, 500));
        $set('error_watch_retention_days', (string)max(1, (int)($_POST['error_watch_retention_days'] ?? 30)));
        $set('container_logs_retention_days', (string)max(1, (int)($_POST['container_logs_retention_days'] ?? 7)));
        $set('error_watch_remediation_url', rtrim(trim($_POST['error_watch_remediation_url'] ?? ''), '/'));
        $set('error_watch_analyze_url',     rtrim(trim($_POST['error_watch_analyze_url'] ?? ''), '/'));
        nm_audit($conn, 'config.save_container_settings', ['target_type'=>'containers']);
        header('Location: net_mon_config.php?tab=containers&saved=1'); exit;
    }

    if ($act==='save_fixkb_settings') {
        $set = function($k,$v) use ($conn){ $v=$conn->real_escape_string($v);
            $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('{$k}','{$v}') ON DUPLICATE KEY UPDATE setting_val='{$v}'"); };
        $set('fix_suggest_url', rtrim(trim($_POST['fix_suggest_url'] ?? ''), '/'));
        $set('fix_webhook_url', rtrim(trim($_POST['fix_webhook_url'] ?? ''), '/'));
        $set('fix_ssh_user',    substr(trim($_POST['fix_ssh_user'] ?? ''), 0, 80));
        $newpass = trim($_POST['fix_ssh_password'] ?? '');
        if ($newpass !== '') $set('fix_ssh_password', nm_secret_encrypt($newpass));
        $set('kb_enabled',  isset($_POST['kb_enabled']) ? '1' : '0');
        $set('kb_ingest_url', rtrim(trim($_POST['kb_ingest_url'] ?? ''), '/'));
        $set('kb_search_url', rtrim(trim($_POST['kb_search_url'] ?? ''), '/'));
        $set('kb_top_k',    (string)max(1, min(10, (int)($_POST['kb_top_k'] ?? 3))));
        $set('kb_min_score',(string)(float)($_POST['kb_min_score'] ?? 0.5));
        $set('books_search_url', rtrim(trim($_POST['books_search_url'] ?? ''), '/'));
        $set('books_top_k', (string)max(1, min(10, (int)($_POST['books_top_k'] ?? 3))));
        nm_audit($conn, 'config.save_fixkb_settings', ['target_type'=>'containers']);
        header('Location: net_mon_config.php?tab=containers&saved=1'); exit;
    }

    if ($act==='save_graylog') {
        $cfg=['url'=>rtrim(trim($_POST['graylog_url']??''),'/'),
              'token'=>trim($_POST['graylog_token']??''),
              'enabled'=>isset($_POST['graylog_enabled'])];
        nm_graylog_save($conn, $cfg);
        nm_audit($conn, 'config.save_graylog', ['target_type'=>'graylog',
            'details'=>['url'=>$cfg['url'],'enabled'=>$cfg['enabled']]]);
        header('Location: net_mon_config.php?tab=integrations&saved=1'); exit;
    }

    if ($act==='add_group') {
        $n = substr(trim($_POST['group_name']??''),0,100);
        $c = preg_match('/^#[0-9a-fA-F]{6}$/',$_POST['group_color']??'') ? $_POST['group_color'] : '#4da3ff';
        if ($n) {
            $st=$conn->prepare("INSERT INTO nm_groups(name,color,sort_order) SELECT ?,?,COALESCE((SELECT MAX(sort_order) FROM nm_groups g2),0)+1");
            $st->bind_param('ss',$n,$c); $st->execute();
        }
        header('Location: net_mon_config.php?tab=nodes&saved=1'); exit;
    }

    if ($act==='del_group') {
        $id=(int)($_POST['group_id']??0);
        if ($id) {
            $conn->query("UPDATE nm_nodes SET group_id=NULL WHERE group_id={$id}");
            $conn->query("DELETE FROM nm_groups WHERE id={$id}");
        }
        header('Location: net_mon_config.php?tab=nodes&saved=1'); exit;
    }

    if ($act==='add_node') {
        $did  = ((int)($_POST['device_id']??0)) ?: null;   // NULL (not 0) when no LibreNMS device — uk_dev is UNIQUE and 0 collides
        $dn   = substr(trim($_POST['display_name']??''),0,100);
        $ip   = substr(trim($_POST['ip_address']??''),0,45);
        $comm = substr(trim($_POST['snmp_community']??''),0,100);
        $ver  = in_array($_POST['snmp_version']??'',['v1','v2c','v3']) ? $_POST['snmp_version'] : 'v2c';
        $icon = substr(preg_replace('/[^a-z0-9_]/','',strtolower($_POST['os_icon']??'generic')),0,50);
        $mask = substr(trim($_POST['subnet_mask']??'/24'),0,18);
        $gid  = (int)($_POST['group_id']??0) ?: null;
        $uid  = (int)($_SESSION['UID']??0);   // canonical session uid (was $_SESSION['user_id'] which is never set → added_by always 0)
        $mtype = in_array($_POST['monitor_type']??'snmp',['snmp','ping'],true) ? $_POST['monitor_type'] : 'snmp';
        if ($mtype==='ping' && $icon==='generic') $icon='ping';   // sensible default badge
        $a = nm_cfg_read_asset($_POST);
        $lic = nm_lic_can_add_nodes($conn, 1);
        if ($dn && $ip && !$lic['ok']) { header('Location: net_mon_config.php?tab=nodes&lic_block=1'); exit; }
        if ($dn && $ip) {
            $st = $conn->prepare("INSERT INTO nm_nodes
                (lnms_device_id,display_name,ip_address,snmp_community,snmp_version,os_icon,subnet_mask,group_id,added_by,monitor_type,
                 manufacturer,model,serial_number,asset_tag,purchase_date,warranty_expiry,asset_notes)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            $st->bind_param('issssssiissssssss', $did, $dn, $ip, $comm, $ver, $icon, $mask, $gid, $uid, $mtype,
                $a['manufacturer'], $a['model'], $a['serial_number'], $a['asset_tag'], $a['purchase_date'], $a['warranty_expiry'], $a['asset_notes']);
            $st->execute();
            $newId = (int)$conn->insert_id;
            // equipment photo (optional)
            if ($newId && !empty($_FILES['photo']['name'])) {
                $up = nm_media_store_image($_FILES['photo'], 'nodes', 'node'.$newId);
                if (!empty($up['ok'])) { $ps=$conn->prepare("UPDATE nm_nodes SET photo_path=? WHERE id=?"); $ps->bind_param('si',$up['path'],$newId); $ps->execute(); }
            }
        }
        header('Location: net_mon_config.php?tab=nodes&saved=1'); exit;
    }

    if ($act==='edit_node') {
        $nid  = (int)($_POST['node_id']??0);
        $dn   = substr(trim($_POST['display_name']??''),0,100);
        $ip   = substr(trim($_POST['ip_address']??''),0,45);
        $comm = substr(trim($_POST['snmp_community']??''),0,100);
        $ver  = in_array($_POST['snmp_version']??'',['v1','v2c','v3']) ? $_POST['snmp_version'] : 'v2c';
        $icon = substr(preg_replace('/[^a-z0-9_]/','',strtolower($_POST['os_icon']??'generic')),0,50);
        $mask = substr(trim($_POST['subnet_mask']??'/24'),0,18);
        $gw   = (int)($_POST['gateway_node_id']??0) ?: null;
        $gwif = (int)($_POST['gateway_iface_id']??0) ?: null;
        $gid  = (int)($_POST['group_id']??0) ?: null;
        $mtype = in_array($_POST['monitor_type']??'snmp',['snmp','ping'],true) ? $_POST['monitor_type'] : 'snmp';
        if ($mtype==='ping' && $icon==='generic') $icon='ping';
        $a = nm_cfg_read_asset($_POST);
        if ($nid && $dn) {
            $st = $conn->prepare("UPDATE nm_nodes SET display_name=?,ip_address=?,snmp_community=?,snmp_version=?,os_icon=?,subnet_mask=?,gateway_node_id=?,gateway_iface_id=?,group_id=?,monitor_type=?,
                manufacturer=?,model=?,serial_number=?,asset_tag=?,purchase_date=?,warranty_expiry=?,asset_notes=? WHERE id=?");
            $st->bind_param('sssssssiissssssssi', $dn, $ip, $comm, $ver, $icon, $mask, $gw, $gwif, $gid, $mtype,
                $a['manufacturer'], $a['model'], $a['serial_number'], $a['asset_tag'], $a['purchase_date'], $a['warranty_expiry'], $a['asset_notes'], $nid);
            $st->execute();
            // equipment photo: replace (delete old) or remove on request
            $curPhoto = null;
            $pr = $conn->query("SELECT photo_path FROM nm_nodes WHERE id=".(int)$nid." LIMIT 1");
            if ($pr && ($px=$pr->fetch_assoc())) $curPhoto = $px['photo_path'];
            if (!empty($_FILES['photo']['name'])) {
                $up = nm_media_store_image($_FILES['photo'], 'nodes', 'node'.$nid);
                if (!empty($up['ok'])) {
                    $ps=$conn->prepare("UPDATE nm_nodes SET photo_path=? WHERE id=?"); $ps->bind_param('si',$up['path'],$nid); $ps->execute();
                    nm_media_delete($curPhoto);
                }
            } elseif (!empty($_POST['remove_photo']) && $curPhoto) {
                $ps=$conn->query("UPDATE nm_nodes SET photo_path=NULL WHERE id=".(int)$nid);
                nm_media_delete($curPhoto);
            }
            // map coordinates (nm_node_geo) for the NOC geo wall — optional
            $glat = $_POST['geo_lat'] ?? ''; $glon = $_POST['geo_lon'] ?? '';
            if (is_numeric($glat) && is_numeric($glon)) {
                nm_geomap_set_geo($conn, $nid, (float)$glat, (float)$glon,
                    $_POST['geo_city'] ?? null, $_POST['geo_country'] ?? null,
                    in_array($_POST['geo_link_type']??'fiber',['fiber','microwave','satellite','copper'],true)?$_POST['geo_link_type']:'fiber');
            } elseif ($glat === '' && $glon === '') {
                nm_geomap_del_geo($conn, $nid);
            }
        }
        header('Location: net_mon_config.php?tab=nodes&saved=1'); exit;
    }

    if ($act==='save_settings') {
        $allowed = ['poll_interval_health','poll_interval_ifaces','retention_days',
                    'discovery_enabled','discovery_schedule','discovery_subnets','discovery_communities',
                    'snmp_timeout','snmp_retries','app_timezone','ping_fail_threshold','snmp_stale_minutes'];
        foreach ($allowed as $key) {
            if (!isset($_POST[$key])) continue;
            $val = substr(trim($_POST[$key]),0,500);
            if ($key==='app_timezone' && !in_array($val, timezone_identifiers_list(), true)) $val = 'America/Puerto_Rico';
            $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('{$key}','{$conn->real_escape_string($val)}')
                ON DUPLICATE KEY UPDATE setting_val='{$conn->real_escape_string($val)}'");
        }
        header('Location: net_mon_config.php?tab=settings&saved=1'); exit;
    }

    // Particle-background alert feeds (own form/action so it never clashes with the other save_settings forms)
    if ($act==='save_netbg') {
        $set = function($k,$v) use ($conn){ $v=$conn->real_escape_string($v);
            $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('{$k}','{$v}') ON DUPLICATE KEY UPDATE setting_val='{$v}'"); };
        $set('netbg_show_errors', isset($_POST['netbg_show_errors']) ? '1':'0');
        $set('netbg_show_events', isset($_POST['netbg_show_events']) ? '1':'0');
        if (function_exists('nm_audit')) nm_audit($conn, 'config.save_netbg', ['target_type'=>'settings']);
        header('Location: net_mon_config.php?tab=settings&saved=1'); exit;
    }

    if ($act==='del_node') {
        $id=(int)($_POST['node_id']??0);
        if ($id) {
            $conn->query("DELETE FROM nm_interfaces WHERE node_id={$id}");
            $conn->query("DELETE FROM nm_nodes WHERE id={$id}");
        }
        header('Location: net_mon_config.php?tab=nodes&saved=1'); exit;
    }

    if ($act==='save_snmp') {
        $id   = (int)($_POST['node_id'] ?? 0);
        $comm = substr(trim($_POST['snmp_community'] ?? ''), 0, 100);
        $ver  = in_array($_POST['snmp_version'] ?? '', ['v1','v2c','v3']) ? $_POST['snmp_version'] : 'v2c';
        if ($id) {
            $st = $conn->prepare("UPDATE nm_nodes SET snmp_community=?, snmp_version=? WHERE id=?");
            $st->bind_param('ssi', $comm, $ver, $id);
            $st->execute();
        }
        header('Location: net_mon_config.php?tab=nodes&saved=1'); exit;
    }

    if ($act==='add_custom_tpl') {
        $n = substr(trim($_POST['tpl_name'] ?? ''), 0, 100);
        $d = substr(trim($_POST['tpl_desc'] ?? ''), 0, 500);
        $o = substr(preg_replace('/[^a-z0-9_]/','',strtolower($_POST['tpl_os'] ?? 'generic')), 0, 50);
        if ($n) {
            $st = $conn->prepare("INSERT INTO nm_oid_templates(name,os_type,description,is_builtin) VALUES(?,?,?,0)");
            $st->bind_param('sss',$n,$o,$d); $st->execute();
        }
        header('Location: net_mon_config.php?tab=snmp&saved=1'); exit;
    }

    if ($act==='del_custom_tpl') {
        $id = (int)($_POST['tpl_id'] ?? 0);
        if ($id) {
            $r = $conn->query("SELECT is_builtin FROM nm_oid_templates WHERE id={$id} LIMIT 1");
            $row = $r ? $r->fetch_assoc() : null;
            if ($row && !$row['is_builtin']) {
                $conn->query("DELETE FROM nm_oid_configs WHERE template_id={$id}");
                $conn->query("DELETE FROM nm_oid_templates WHERE id={$id}");
            }
        }
        header('Location: net_mon_config.php?tab=snmp&saved=1'); exit;
    }

}

// ─── Load page data ───────────────────────────────────────────────────────────
$tab    = in_array($_GET['tab']??'',['settings','connection','nodes','interfaces','links','poller','snmp','discovery','integrations','credentials','containers','switches','databases']) ? $_GET['tab'] : 'settings';
if ($tab === 'connection') $tab = 'settings'; // redirect old bookmarks
$_graylog_cfg = nm_graylog_get($conn);
$_n8n_cfg     = nm_n8n_get($conn);
// AI Gateway (metered NEURU AI Flows service) — the vkey + connection key the customer
// pastes after registering their install on the NEURU Portal. Injected into flow calls.
$_ai_gw = ['vkey'=>'','conn_key'=>'','public_base'=>''];
if ($__r = @$conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ('ai_gateway_vkey','ai_conn_key','ai_public_base')")) {
    while ($__x = $__r->fetch_assoc()) {
        if     ($__x['setting_key']==='ai_gateway_vkey') $_ai_gw['vkey']        = $__x['setting_val'];
        elseif ($__x['setting_key']==='ai_conn_key')     $_ai_gw['conn_key']    = $__x['setting_val'];
        elseif ($__x['setting_key']==='ai_public_base')  $_ai_gw['public_base'] = $__x['setting_val'];
    }
}
// Adv. Solution Commander (Router Commander) webhooks
$_rc = ['suggest'=>'','execute'=>''];
if ($__rcq = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ('rc_suggest_url','rc_execute_url')")) {
    while ($__x = $__rcq->fetch_assoc()) { if ($__x['setting_key']==='rc_suggest_url') $_rc['suggest']=$__x['setting_val']; else $_rc['execute']=$__x['setting_val']; }
}
$_portainer_cfg = nm_portainer_cfg($conn);
$_portainer_haskey = ($_portainer_cfg['key'] ?? '') !== '';
// Smokeping (optional embedded latency tool + remote target management)
$_sp = ['url'=>'', 'enabled'=>false, 'host_ip'=>'', 'container'=>'smokeping', 'targets_path'=>'/config/Targets', 'data_path'=>'/data', 'manage_url'=>'', 'reload_cmd'=>''];
if ($_r = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key LIKE 'smokeping_%'")) {
    while ($x = $_r->fetch_assoc()) {
        switch ($x['setting_key']) {
            case 'smokeping_url':          $_sp['url'] = $x['setting_val']; break;
            case 'smokeping_enabled':      $_sp['enabled'] = $x['setting_val']==='1'; break;
            case 'smokeping_host_ip':      $_sp['host_ip'] = $x['setting_val']; break;
            case 'smokeping_container':    if ($x['setting_val']!=='') $_sp['container'] = $x['setting_val']; break;
            case 'smokeping_targets_path': if ($x['setting_val']!=='') $_sp['targets_path'] = $x['setting_val']; break;
            case 'smokeping_data_path':    if ($x['setting_val']!=='') $_sp['data_path'] = $x['setting_val']; break;
            case 'smokeping_manage_url':   $_sp['manage_url'] = $x['setting_val']; break;
            case 'smokeping_reload_cmd':   $_sp['reload_cmd'] = $x['setting_val']; break;
            case 'smokeping_alerts_enabled': $_sp['alerts_enabled'] = $x['setting_val']!=='0'; break;
            case 'smokeping_alert_sustain':  $_sp['alert_sustain'] = (int)$x['setting_val'] ?: 2; break;
            case 'smokeping_alert_url':       $_sp['alert_url'] = $x['setting_val']; break;
        }
    }
}
$_sp += ['alerts_enabled'=>true, 'alert_sustain'=>2, 'alert_url'=>''];
require_once __DIR__ . '/nm_smokeping.php';
$_sp_thr = nm_sp_thresholds($conn)['global'];

// Pi-hole servers (multi-instance; passwords never echoed back to the form)
require_once __DIR__ . '/nm_pihole.php';
$_ph_servers = nm_ph_servers($conn);

// NetFlow settings + live collector status
require_once __DIR__ . '/nm_netflow.php';
$_nf = nm_nf_settings($conn);
$_nf_status = nm_nf_status($conn);

// SMTP (email delivery for notifications)
require_once __DIR__ . '/nm_smtp.php';
$_smtp = nm_smtp_settings($conn);

// NEURU syslog server settings + status
$_sy = ['log_source'=>'syslog','syslog_port'=>'514','syslog_retention_days'=>'30','syslog_tcp_enabled'=>true];
if ($_r = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ('log_source','syslog_port','syslog_retention_days','syslog_tcp_enabled')")) {
    while ($x = $_r->fetch_assoc()) {
        if ($x['setting_key']==='syslog_tcp_enabled') $_sy['syslog_tcp_enabled'] = $x['setting_val']!=='0';
        else $_sy[$x['setting_key']] = $x['setting_val'];
    }
}
$_cset = [];
if ($conn->query("SHOW TABLES LIKE 'nm_settings'")->num_rows > 0) {
    $cr = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key LIKE 'error_watch_%' OR setting_key LIKE 'fix_%' OR setting_key LIKE 'kb_%' OR setting_key LIKE 'books_%' OR setting_key IN('container_logs_retention_days','container_logs_collect')");
    while ($cr && $row = $cr->fetch_assoc()) $_cset[$row['setting_key']] = $row['setting_val'];
    $_fix_haspass = isset($_cset['fix_ssh_password']) && $_cset['fix_ssh_password'] !== '';
}
function cset($k,$d=''){ global $_cset; return $_cset[$k] ?? $d; }
$saved  = isset($_GET['saved']);
$groups = $conn->query("SELECT * FROM nm_groups ORDER BY sort_order,name")->fetch_all(MYSQLI_ASSOC);
$nodes  = $conn->query("SELECT n.id,n.lnms_device_id,n.display_name,n.ip_address,n.os_icon,
    n.snmp_community,n.snmp_version,n.oid_template_id,n.subnet_mask,n.gateway_node_id,n.gateway_iface_id,n.group_id,n.monitor_type,
    n.photo_path,n.manufacturer,n.model,n.serial_number,n.asset_tag,n.purchase_date,n.warranty_expiry,n.asset_notes,
    g.name grp_name,g.color grp_color
    FROM nm_nodes n LEFT JOIN nm_groups g ON g.id=n.group_id
    ORDER BY g.sort_order,n.sort_order,n.display_name")->fetch_all(MYSQLI_ASSOC);

// Interfaces per node (for the gateway-interface picker on the edit form)
$node_ifaces = [];
$ir = $conn->query("SELECT id,node_id,if_name,display_name,if_ip_address FROM nm_interfaces WHERE show_graph=1 ORDER BY node_id,sort_order,if_index");
if ($ir) while ($r = $ir->fetch_assoc()) $node_ifaces[(int)$r['node_id']][] = $r;

// NM global settings
$nm_settings = [];
if ($conn->query("SHOW TABLES LIKE 'nm_settings'")->num_rows > 0) {
    $sr = $conn->query("SELECT setting_key, setting_val FROM nm_settings");
    while ($r=$sr->fetch_assoc()) $nm_settings[$r['setting_key']] = $r['setting_val'];
}
function nms($key, $default='') { global $nm_settings; return $nm_settings[$key] ?? $default; }

// Data for SNMP OIDs tab
$oid_templates = $conn->query("SELECT t.*,(SELECT COUNT(*) FROM nm_oid_configs WHERE template_id=t.id) oid_count FROM nm_oid_templates t ORDER BY t.is_builtin DESC,t.name")->fetch_all(MYSQLI_ASSOC);
$tpl_map = []; foreach ($oid_templates as $t) $tpl_map[$t['id']] = $t['name'];

$iface_node_id = (int)($_GET['node']??($nodes[0]['id']??0));

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php');
log_user_action($conn,'view_page','net_mon_config.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Monitor — Config | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="/leaflet.min.js"></script>
<style>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#4da3ff;--up:#2ecc71;--down:#e74c3c;--warn:#f39c12;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#000;color:#fff;overflow-x:hidden;}
#bg-video{position:fixed;top:0;left:0;min-width:100%;min-height:100%;z-index:-1;object-fit:cover;opacity:0.35;}
.pw{max-width:1400px;margin:0 auto;padding:20px;box-sizing:border-box;}

/* ── Header ── */
.pg-header{display:flex;align-items:center;margin-bottom:18px;}
.pg-title-card{flex:1;background:linear-gradient(120deg,rgba(77,163,255,.10),rgba(255,255,255,0.04));backdrop-filter:blur(15px);border:1px solid var(--border);border-radius:18px;padding:20px 28px;display:flex;align-items:center;gap:22px;position:relative;overflow:hidden;}
.pg-title-card::before{content:'';position:absolute;left:0;top:0;width:4px;height:100%;background:var(--accent);box-shadow:0 0 15px var(--accent);}
.pg-title-icon{display:flex;align-items:center;justify-content:center;width:54px;height:54px;border-radius:14px;background:rgba(77,163,255,.12);border:1px solid rgba(77,163,255,.3);font-size:26px;color:var(--accent);flex-shrink:0;}
.pg-title{margin:0;font-size:28px;letter-spacing:-.5px;line-height:1.1;}
.pg-sub{font-size:12.5px;color:#9aa;margin-top:5px;}
.back-btn{background:rgba(77,163,255,.12);border:1px solid var(--accent);color:var(--accent);padding:10px 20px;border-radius:10px;cursor:pointer;font-size:13px;font-weight:600;text-decoration:none;display:flex;align-items:center;gap:8px;transition:.2s;white-space:nowrap;flex-shrink:0;}
.back-btn:hover{background:var(--accent);color:#000;}
@media(max-width:720px){.pg-title-card{flex-wrap:wrap;gap:14px;padding:16px 18px;}.pg-title{font-size:22px;}.back-btn{order:3;}}

/* ── Tabs (real tab strip) ── */
.tab-bar{display:flex;flex-wrap:wrap;gap:2px;margin-bottom:18px;border-bottom:1px solid var(--border);}
.tab-btn{background:transparent;border:none;border-bottom:2px solid transparent;color:#9aa;padding:11px 18px;cursor:pointer;font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;transition:.16s;border-radius:8px 8px 0 0;margin-bottom:-1px;white-space:nowrap;}
.tab-btn:hover{color:#fff;background:rgba(255,255,255,0.05);}
.tab-btn.active{color:var(--accent);border-bottom-color:var(--accent);background:rgba(77,163,255,.09);}
.tab-btn .tab-badge{font-size:10px;font-weight:700;background:rgba(255,255,255,.1);color:#ccd;padding:1px 7px;border-radius:10px;}
.tab-btn.active .tab-badge{background:rgba(77,163,255,.25);color:#cfe4ff;}
.tab-panel{display:none;animation:tabfade .2s ease;}
.tab-panel.active{display:block;}
@keyframes tabfade{from{opacity:0;transform:translateY(4px);}to{opacity:1;transform:none;}}

/* ── Cards ── */
.glass-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:15px;padding:20px;margin-bottom:15px;}
h2{margin:0 0 18px;font-size:16px;color:var(--accent);display:flex;align-items:center;gap:10px;}

/* ── Two-column layout ── */
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:15px;}
@media(max-width:900px){.two-col{grid-template-columns:1fr;}}
/* two balanced flex columns for the Integrations & AI tab — vertical stacks, never overlap */
.int-masonry{display:flex;gap:15px;align-items:flex-start;}
.int-masonry > .im-col{flex:1 1 0;min-width:0;display:flex;flex-direction:column;gap:15px;}
.int-masonry .glass-card{margin:0!important;}
@media(max-width:1100px){.int-masonry{flex-direction:column;}.int-masonry > .im-col{width:100%;}}

/* ── Form elements ── */
.form-row{display:flex;flex-direction:column;gap:5px;margin-bottom:14px;}
.form-row label{font-size:12px;color:#aaa;text-transform:uppercase;letter-spacing:.8px;}
.form-input{background:rgba(255,255,255,0.08);border:1px solid var(--border);color:#fff;padding:9px 14px;border-radius:8px;font-size:13px;outline:none;transition:.2s;width:100%;box-sizing:border-box;}
.form-input:focus{border-color:var(--accent);}
.form-select{background:rgba(20,30,50,0.9);border:1px solid var(--border);color:#fff;padding:9px 14px;border-radius:8px;font-size:13px;outline:none;width:100%;box-sizing:border-box;}
.form-select:focus{border-color:var(--accent);}
.form-row-inline{display:flex;gap:10px;align-items:flex-end;}

/* ── Buttons ── */
.btn{padding:9px 20px;border-radius:9px;cursor:pointer;font-size:13px;font-weight:600;border:1px solid;display:inline-flex;align-items:center;gap:7px;transition:.2s;}
.btn-primary{background:rgba(77,163,255,.15);border-color:var(--accent);color:var(--accent);}
.btn-primary:hover{background:var(--accent);color:#000;}
.btn-success{background:rgba(46,204,113,.15);border-color:var(--up);color:var(--up);}
.btn-success:hover{background:var(--up);color:#000;}
.btn-danger{background:rgba(231,76,60,.12);border-color:var(--down);color:var(--down);}
.btn-danger:hover{background:var(--down);color:#fff;}
.btn-sm{padding:5px 12px;font-size:11px;}

/* ── Flash message ── */
.flash{padding:12px 18px;border-radius:10px;margin-bottom:15px;font-size:13px;font-weight:600;}
.flash-success{background:rgba(46,204,113,.15);border:1px solid var(--up);color:var(--up);}

/* ── Connection status ── */
.conn-status{display:flex;align-items:center;gap:10px;padding:12px 16px;border-radius:10px;margin-bottom:18px;font-size:13px;}
.conn-ok{background:rgba(46,204,113,.1);border:1px solid var(--up);color:var(--up);}
.conn-off{background:rgba(231,76,60,.1);border:1px solid var(--down);color:var(--down);}
.conn-unk{background:rgba(255,255,255,.05);border:1px solid var(--border);color:#888;}

/* ── Toggle ── */
.toggle-wrap{display:flex;align-items:center;gap:12px;}
.toggle-switch{position:relative;display:inline-block;width:44px;height:24px;}
.toggle-switch input{opacity:0;width:0;height:0;}
.toggle-slider{position:absolute;cursor:pointer;inset:0;background:#333;border-radius:24px;transition:.3s;}
.toggle-slider::before{content:'';position:absolute;width:18px;height:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.3s;}
input:checked+.toggle-slider{background:var(--accent);}
input:checked+.toggle-slider::before{transform:translateX(20px);}

/* ── Device browser table ── */
.dev-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px;}
.dev-table th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);color:#888;font-size:11px;text-transform:uppercase;letter-spacing:.8px;}
.dev-table td{padding:7px 10px;border-bottom:1px solid rgba(255,255,255,0.04);vertical-align:middle;}
.dev-table tr:hover td{background:rgba(255,255,255,0.04);}
.os-badge{display:inline-flex;align-items:center;gap:5px;background:rgba(255,255,255,.06);border:1px solid var(--border);border-radius:6px;padding:2px 8px;font-size:10px;}

/* ── Node list ── */
.node-group-header{display:flex;align-items:center;gap:8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#888;margin:12px 0 6px;padding-bottom:6px;border-bottom:1px solid var(--border);}
.node-row{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;margin-bottom:4px;background:rgba(255,255,255,.04);border:1px solid transparent;transition:.2s;}
.node-row:hover{border-color:var(--border);}
.node-row .node-name{flex:1;font-size:13px;font-weight:600;}
.node-row .node-ip{font-size:11px;color:#888;font-family:monospace;}
.node-row .node-group-tag{font-size:10px;padding:2px 8px;border-radius:6px;background:rgba(77,163,255,.12);color:var(--accent);}

/* ── Interface grid ── */
.iface-table{width:100%;border-collapse:collapse;font-size:12px;}
.iface-table th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);color:#888;font-size:11px;text-transform:uppercase;}
.iface-table td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle;}
.iface-table tr:hover td{background:rgba(255,255,255,.03);}
.iface-table tr.selected td{background:rgba(77,163,255,.05);}
.badge-up{background:rgba(46,204,113,.15);color:var(--up);padding:2px 8px;border-radius:6px;font-size:10px;font-weight:700;}
.badge-dn{background:rgba(231,76,60,.15);color:var(--down);padding:2px 8px;border-radius:6px;font-size:10px;font-weight:700;}

/* ── Search input ── */
.search-wrap{position:relative;margin-bottom:10px;}
.search-wrap input{width:100%;box-sizing:border-box;background:rgba(255,255,255,.08);border:1px solid var(--border);color:#fff;padding:8px 14px 8px 36px;border-radius:8px;font-size:12px;outline:none;}
.search-wrap input:focus{border-color:var(--accent);}
.search-wrap i{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:#555;}

/* ── Loader ── */
.spinner{display:inline-block;width:18px;height:18px;border:2px solid rgba(77,163,255,.3);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;}
@keyframes spin{to{transform:rotate(360deg);}}

/* ── Add-node inline form ── */
#add-node-panel{display:none;background:rgba(77,163,255,.05);border:1px solid rgba(77,163,255,.2);border-radius:10px;padding:16px;margin-top:14px;}
#add-node-panel.open{display:block;}

/* ── SNMP OIDs tab ── */
.tpl-card{background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:9px;padding:9px 11px;margin-bottom:7px;transition:.15s;cursor:pointer;display:flex;gap:9px;align-items:flex-start;}
.tpl-card:hover,.tpl-card.active{border-color:var(--accent);background:rgba(77,163,255,.09);}
.tpl-card .tpl-ico{flex-shrink:0;width:26px;height:26px;border-radius:7px;background:rgba(77,163,255,.12);color:var(--accent);display:flex;align-items:center;justify-content:center;font-size:12px;margin-top:1px;}
.tpl-card .tpl-body{flex:1;min-width:0;}
.tpl-card .tpl-name{font-size:12.5px;font-weight:600;color:#fff;display:flex;align-items:center;gap:6px;flex-wrap:wrap;}
.tpl-card .tpl-meta{font-size:10.5px;color:#7c828c;margin-top:2px;}
.tpl-card .tpl-desc{font-size:10.5px;color:#8a909a;margin-top:3px;line-height:1.4;overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;}
.tpl-list{max-height:432px;overflow-y:auto;margin:0 -3px;padding:2px 3px;}
.tpl-list::-webkit-scrollbar{width:7px;} .tpl-list::-webkit-scrollbar-thumb{background:rgba(255,255,255,.16);border-radius:4px;}
.tpl-filter{width:100%;background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:8px;padding:7px 11px;color:#e6e9ee;font-size:12px;margin-bottom:10px;}
.tpl-filter:focus{outline:none;border-color:var(--accent);}
.tpl-empty{font-size:11.5px;color:#666;text-align:center;padding:16px;display:none;}
.tpl-collapse-hd{display:flex;align-items:center;justify-content:space-between;cursor:pointer;font-size:12px;color:#9aa;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);}
.tpl-collapse-hd:hover{color:#cfe4ff;}
.oid-row{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:8px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);margin-bottom:5px;font-size:11px;}
.oid-row .oid-name{font-weight:600;color:#fff;min-width:120px;}
.oid-row .oid-string{font-family:monospace;color:#4da3ff;font-size:10px;flex:1;}
.oid-row .oid-badge{padding:1px 7px;border-radius:5px;font-size:9px;font-weight:700;text-transform:uppercase;}
.oid-type-cpu{background:rgba(77,163,255,.2);color:#4da3ff;}
.oid-type-memory{background:rgba(46,204,113,.15);color:#2ecc71;}
.oid-type-disk{background:rgba(243,156,18,.15);color:#f39c12;}
.oid-type-temperature{background:rgba(231,76,60,.15);color:#e74c3c;}
.oid-type-custom{background:rgba(255,255,255,.08);color:#aaa;}
.builtin-badge{background:rgba(77,163,255,.1);border:1px solid rgba(77,163,255,.3);color:#4da3ff;padding:1px 7px;border-radius:5px;font-size:9px;font-weight:700;}
.custom-badge{background:rgba(46,204,113,.1);border:1px solid rgba(46,204,113,.3);color:#2ecc71;padding:1px 7px;border-radius:5px;font-size:9px;font-weight:700;}
.snmp-3col{display:grid;grid-template-columns:300px 1fr 400px;gap:15px;align-items:start;}
@media(max-width:1200px){.snmp-3col{grid-template-columns:1fr 1fr;}}
@media(max-width:800px){.snmp-3col{grid-template-columns:1fr;}}
.form-mini input,.form-mini select{padding:6px 10px;font-size:12px;}
/* SNMP plain-language explainer */
.snmp-intro{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:14px;padding:16px 18px;margin-bottom:16px;}
.snmp-intro-head{font-size:13px;color:#cfd6df;line-height:1.6;margin-bottom:14px;}
.snmp-intro-head i{color:var(--accent);margin-right:6px;}
.snmp-intro-head b{color:#fff;}
.snmp-intro-head span{color:#9aa;}
.snmp-steps{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;}
@media(max-width:850px){.snmp-steps{grid-template-columns:1fr;}}
.snmp-step{display:flex;gap:12px;background:rgba(77,163,255,.05);border:1px solid rgba(77,163,255,.18);border-radius:10px;padding:12px 14px;}
.snmp-step-n{flex-shrink:0;width:26px;height:26px;border-radius:50%;background:var(--accent);color:#04111f;font-weight:800;font-size:13px;display:flex;align-items:center;justify-content:center;}
.snmp-step b{font-size:12.5px;color:#fff;}
.snmp-step p{margin:4px 0 0;font-size:11.5px;color:#9aa;line-height:1.55;}
.snmp-step p b{color:#cfe4ff;font-weight:600;}
.snmp-sec-tag{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:rgba(77,163,255,.18);border:1px solid rgba(77,163,255,.4);color:var(--accent);font-size:12px;font-weight:800;margin-right:8px;}
.fhelp{font-size:10.5px;color:#6b7280;margin-top:3px;line-height:1.45;}
.adv-tag{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:#f39c12;background:rgba(243,156,18,.12);border:1px solid rgba(243,156,18,.3);padding:1px 7px;border-radius:5px;margin-left:8px;}
</style>
</head>
<body>
<video autoplay muted loop playsinline id="bg-video">
    <source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4">
</video>

<div class="pw">

<!-- ── Page Header ──────────────────────────────────────────────────────── -->
<div class="pg-header">
    <div class="pg-title-card">
        <div class="pg-title-icon"><i class="fas fa-network-wired"></i></div>
        <div style="flex:1;min-width:0;">
            <h1 class="pg-title">Network Monitor <span style="font-weight:300;">Configuration</span></h1>
            <div class="pg-sub">Add &amp; manage devices · SNMP &amp; OIDs · Interfaces · Discovery · Integrations &amp; AI · Global settings</div>
        </div>
        <a href="net_mon.php" class="back-btn"><i class="fas fa-arrow-left"></i> Live Dashboard</a>
    </div>
</div>

<?php if ($saved): ?>
<div class="flash flash-success"><i class="fas fa-check-circle"></i> Changes saved successfully.</div>
<?php endif ?>

<!-- ── Tab Bar ──────────────────────────────────────────────────────────── -->
<div class="tab-bar">
    <button class="tab-btn <?= $tab==='settings'?'active':'' ?>" onclick="showTab('settings')">
        <i class="fas fa-sliders"></i> Settings
    </button>
    <button class="tab-btn <?= $tab==='nodes'?'active':'' ?>" onclick="showTab('nodes')">
        <i class="fas fa-server"></i> Nodes <span id="nodes-count" style="font-size:10px;opacity:.7;">(<?= count($nodes) ?>)</span>
    </button>
    <button class="tab-btn <?= $tab==='interfaces'?'active':'' ?>" onclick="showTab('interfaces');loadNodeIfacesDirect()">
        <i class="fas fa-ethernet"></i> Interfaces
    </button>
    <button class="tab-btn <?= $tab==='links'?'active':'' ?>" onclick="showTab('links');loadLinks()">
        <i class="fas fa-diagram-project"></i> Connections
    </button>
    <button class="tab-btn <?= $tab==='poller'?'active':'' ?>" onclick="showTab('poller')">
        <i class="fas fa-clock-rotate-left"></i> Poller
    </button>
    <button class="tab-btn <?= $tab==='snmp'?'active':'' ?>" onclick="showTab('snmp');loadNodeOids()">
        <i class="fas fa-code-branch"></i> SNMP &amp; OIDs
    </button>
    <button class="tab-btn <?= $tab==='discovery'?'active':'' ?>" onclick="showTab('discovery');loadCandidates()">
        <i class="fas fa-radar"></i> Discovery
        <?php
        $pending_ct = 0;
        if ($conn->query("SHOW TABLES LIKE 'nm_discovery_candidates'")->num_rows > 0) {
            $pct = $conn->query("SELECT COUNT(*) FROM nm_discovery_candidates WHERE status='pending'");
            $pending_ct = $pct ? (int)$pct->fetch_row()[0] : 0;
        }
        if ($pending_ct > 0): ?>
        <span style="background:#f39c12;color:#000;border-radius:10px;padding:1px 6px;font-size:9px;font-weight:700;"><?= $pending_ct ?></span>
        <?php endif ?>
    </button>
    <button class="tab-btn <?= $tab==='integrations'?'active':'' ?>" onclick="showTab('integrations');loadWebhooks()">
        <i class="fas fa-robot"></i> Integrations &amp; AI
    </button>
    <button class="tab-btn <?= $tab==='credentials'?'active':'' ?>" onclick="showTab('credentials');loadSsh()">
        <i class="fas fa-key"></i> Credentials
    </button>
    <button class="tab-btn <?= $tab==='switches'?'active':'' ?>" onclick="showTab('switches');loadL2()">
        <i class="fas fa-ethernet"></i> Unmanaged Switches
    </button>
    <button class="tab-btn <?= $tab==='containers'?'active':'' ?>" onclick="showTab('containers')">
        <i class="fab fa-docker"></i> Containers
    </button>
    <button class="tab-btn <?= $tab==='databases'?'active':'' ?>" onclick="showTab('databases');loadDbs()">
        <i class="fas fa-database"></i> Databases
    </button>
</div>

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 1: Settings                                                         -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-settings" class="tab-panel <?= $tab==='settings'?'active':'' ?>">
<div class="two-col">

<!-- NM Global Settings -->
<div class="glass-card">
    <h2><i class="fas fa-sliders"></i> Network Monitor — Global Settings</h2>
    <form method="post">
        <input type="hidden" name="action" value="save_settings">
        <div class="form-row">
            <label>Health Poll Interval (seconds)</label>
            <select class="form-select" name="poll_interval_health">
                <?php foreach ([30=>'30s',60=>'1 min',120=>'2 min',300=>'5 min',600=>'10 min'] as $v=>$l): ?>
                <option value="<?= $v ?>" <?= nms('poll_interval_health','60')==$v?'selected':'' ?>><?= $l ?></option>
                <?php endforeach ?>
            </select>
            <span style="font-size:11px;color:#555;margin-top:3px;">CPU, memory, disk polling interval</span>
        </div>
        <div class="form-row">
            <label>Interface Poll Interval (seconds)</label>
            <select class="form-select" name="poll_interval_ifaces">
                <?php foreach ([30=>'30s',60=>'1 min',120=>'2 min',300=>'5 min',600=>'10 min'] as $v=>$l): ?>
                <option value="<?= $v ?>" <?= nms('poll_interval_ifaces','60')==$v?'selected':'' ?>><?= $l ?></option>
                <?php endforeach ?>
            </select>
            <span style="font-size:11px;color:#555;margin-top:3px;">Traffic counter polling interval</span>
        </div>
        <div class="form-row">
            <label>Data Retention (days)</label>
            <select class="form-select" name="retention_days">
                <?php foreach ([7=>'7 days',14=>'14 days',30=>'30 days',60=>'60 days',90=>'90 days',180=>'180 days',365=>'1 year'] as $v=>$l): ?>
                <option value="<?= $v ?>" <?= nms('retention_days','30')==$v?'selected':'' ?>><?= $l ?></option>
                <?php endforeach ?>
            </select>
        </div>
        <div class="form-row">
            <label>SNMP Timeout (seconds)</label>
            <select class="form-select" name="snmp_timeout">
                <?php foreach ([2=>'2s',3=>'3s',5=>'5s',10=>'10s'] as $v=>$l): ?>
                <option value="<?= $v ?>" <?= nms('snmp_timeout','3')==$v?'selected':'' ?>><?= $l ?></option>
                <?php endforeach ?>
            </select>
        </div>
        <div class="form-row">
            <label>SNMP Retries</label>
            <select class="form-select" name="snmp_retries">
                <?php foreach ([0=>'0',1=>'1',2=>'2',3=>'3'] as $v=>$l): ?>
                <option value="<?= $v ?>" <?= nms('snmp_retries','1')==$v?'selected':'' ?>><?= $l ?></option>
                <?php endforeach ?>
            </select>
        </div>
        <div class="form-row">
            <label><i class="fas fa-heart-pulse"></i> Ping Down Sensitivity</label>
            <select class="form-select" name="ping_fail_threshold">
                <?php foreach ([1=>'1 failed check (instant — most twitchy)',2=>'2 failed checks (~2 min)',3=>'3 failed checks (~3 min — recommended)',4=>'4 failed checks (~4 min)',5=>'5 failed checks (~5 min — strictest)'] as $v=>$l): ?>
                <option value="<?= $v ?>" <?= (int)nms('ping_fail_threshold','3')===$v?'selected':'' ?>><?= $l ?></option>
                <?php endforeach ?>
            </select>
            <span style="font-size:11px;color:#555;margin-top:3px;">Consecutive failed ICMP polls (1/min) before a ping node is declared DOWN. Lower = faster detection but more false alarms; higher = fewer false alarms. Recovery is always instant.</span>
        </div>
        <div class="form-row">
            <label><i class="fas fa-satellite-dish"></i> SNMP Stale Sensitivity</label>
            <select class="form-select" name="snmp_stale_minutes">
                <?php foreach ([6=>'6 min (~2 missed polls — fastest)',8=>'8 min',11=>'11 min (recommended)',15=>'15 min',20=>'20 min (most tolerant)'] as $v=>$l): ?>
                <option value="<?= $v ?>" <?= (int)nms('snmp_stale_minutes','11')===$v?'selected':'' ?>><?= $l ?></option>
                <?php endforeach ?>
            </select>
            <span style="font-size:11px;color:#555;margin-top:3px;">Minutes of SNMP silence (no interface OR health telemetry) before a node is flagged. If it still answers ICMP → <b>DEGRADED</b> (SNMP agent/service down but host up); if it also fails ping → <b>DOWN</b>. This is what catches "I stopped a service/VM but the box still pings."</span>
        </div>
        <div class="form-row" style="border-top:1px solid rgba(255,255,255,.08);margin-top:10px;padding-top:12px;">
            <label><i class="fas fa-clock"></i> Display Timezone</label>
            <select class="form-select" name="app_timezone">
                <?php $_curtz=nms('app_timezone','America/Puerto_Rico'); $_grp=[];
                foreach (timezone_identifiers_list() as $z){ $p=strpos($z,'/')!==false?substr($z,0,strpos($z,'/')):'Other'; $_grp[$p][]=$z; }
                foreach ($_grp as $region=>$zs): ?>
                <optgroup label="<?= htmlspecialchars($region) ?>">
                    <?php foreach ($zs as $z): ?><option value="<?= htmlspecialchars($z) ?>" <?= $_curtz===$z?'selected':'' ?>><?= htmlspecialchars($z) ?></option><?php endforeach ?>
                </optgroup>
                <?php endforeach ?>
            </select>
            <span style="font-size:11px;color:#555;margin-top:3px;">Every page shows times in this zone (storage stays UTC). Default America/Puerto_Rico.</span>
        </div>
        <button type="submit" class="btn btn-success" style="margin-top:8px;">
            <i class="fas fa-floppy-disk"></i> Save Settings
        </button>
    </form>

    <!-- Particle-background alert overlays -->
    <form method="post" style="border-top:1px solid rgba(255,255,255,.08);margin-top:16px;padding-top:14px;">
        <input type="hidden" name="action" value="save_netbg">
        <h2 style="font-size:14px;"><i class="fas fa-wave-square"></i> Background Alert Overlays</h2>
        <p style="font-size:11px;color:#666;margin:2px 0 12px;">Control the glowing labels the animated particle background shows on every page. Turn them off for a calmer, distraction-free backdrop — this does NOT affect real alerting/notifications, only the decorative overlay.</p>
        <div class="form-row">
            <div class="toggle-wrap">
                <label class="toggle-switch"><input type="checkbox" name="netbg_show_errors" <?= nms('netbg_show_errors','1')!=='0'?'checked':'' ?>><span class="toggle-slider"></span></label>
                <div><label style="margin:0;"><i class="fas fa-triangle-exclamation" style="color:#e74c3c;"></i> Container errors</label>
                    <div style="font-size:11px;color:#666;">Red markers for open container/error-watch incidents.</div></div>
            </div>
        </div>
        <div class="form-row">
            <div class="toggle-wrap">
                <label class="toggle-switch"><input type="checkbox" name="netbg_show_events" <?= nms('netbg_show_events','1')!=='0'?'checked':'' ?>><span class="toggle-slider"></span></label>
                <div><label style="margin:0;"><i class="fas fa-bolt" style="color:#f39c12;"></i> Network events</label>
                    <div style="font-size:11px;color:#666;">Markers for open network incidents/events (device down, high loss, anomalies…).</div></div>
            </div>
        </div>
        <button type="submit" class="btn btn-success" style="margin-top:8px;"><i class="fas fa-floppy-disk"></i> Save Overlays</button>
    </form>
</div>

<!-- Auto-Discovery Settings -->
<div>
<div class="glass-card">
    <h2><i class="fas fa-radar"></i> Auto-Discovery</h2>
    <form method="post">
        <input type="hidden" name="action" value="save_settings">
        <div class="form-row">
            <label>Discovery Schedule</label>
            <select class="form-select" name="discovery_schedule">
                <option value="manual" <?= nms('discovery_schedule','manual')==='manual'?'selected':'' ?>>Manual only</option>
                <option value="daily"  <?= nms('discovery_schedule')==='daily'?'selected':'' ?>>Daily</option>
                <option value="weekly" <?= nms('discovery_schedule')==='weekly'?'selected':'' ?>>Weekly</option>
            </select>
            <span style="font-size:11px;color:#555;margin-top:3px;">Scheduled runs show pending devices for review — never auto-add without your approval</span>
        </div>
        <div class="form-row">
            <label>Subnets to Scan (comma-separated CIDR)</label>
            <input class="form-input" type="text" name="discovery_subnets" placeholder="192.168.10.0/24, 10.10.0.0/24"
                   value="<?= htmlspecialchars(nms('discovery_subnets','')) ?>">
        </div>
        <div class="form-row">
            <label>SNMP Communities to Try (comma-separated)</label>
            <input class="form-input" type="text" name="discovery_communities" placeholder="public, private, community1"
                   value="<?= htmlspecialchars(nms('discovery_communities','public')) ?>">
            <span style="font-size:11px;color:#555;margin-top:3px;">Community strings already on monitored nodes are always tried automatically</span>
        </div>
        <input type="hidden" name="discovery_enabled" value="<?= nms('discovery_enabled','0') ?>">
        <?php if (nms('discovery_last_run')): ?>
        <div style="font-size:11px;color:#555;margin-bottom:8px;"><i class="fas fa-clock"></i> Last run: <?= htmlspecialchars(nms('discovery_last_run')) ?></div>
        <?php endif ?>
        <button type="submit" class="btn btn-success" style="margin-top:8px;">
            <i class="fas fa-floppy-disk"></i> Save Discovery Settings
        </button>
    </form>
</div>

<!-- LibreNMS Legacy Fallback -->
<div class="glass-card" style="border-color:rgba(243,156,18,.3);">
    <h2 style="color:var(--warn);"><i class="fas fa-plug"></i> LibreNMS — Legacy Fallback</h2>
    <p style="font-size:11px;color:#888;margin:0 0 14px;">Used only for nodes that have no SNMP community configured. All direct-SNMP nodes bypass this entirely.</p>

    <div id="conn-status" class="conn-status conn-unk" style="margin-bottom:14px;">
        <i class="fas fa-circle-question"></i>
        <span id="conn-status-text">Click "Test" to check status.</span>
    </div>

    <form method="post">
        <input type="hidden" name="action" value="save_lnms">
        <div class="form-row">
            <label>LibreNMS URL</label>
            <input class="form-input" type="text" name="lnms_url" value="<?= htmlspecialchars(NMC_URL) ?>" placeholder="http://192.168.x.x:8080" autocomplete="off">
        </div>
        <div class="form-row">
            <label>API Token</label>
            <input class="form-input" type="password" name="lnms_token" value="<?= htmlspecialchars(NMC_TOKEN) ?>" placeholder="LibreNMS API token">
        </div>
        <div class="form-row">
            <label>Enable Fallback</label>
            <div class="toggle-wrap">
                <label class="toggle-switch">
                    <input type="checkbox" name="lnms_enabled" id="lnms-enabled-chk" <?= $_lnms_cfg['enabled']?'checked':'' ?>>
                    <span class="toggle-slider"></span>
                </label>
                <span id="enabled-lbl" style="font-size:12px;color:<?= $_lnms_cfg['enabled']?'var(--up)':'var(--down)' ?>;">
                    <?= $_lnms_cfg['enabled']?'Enabled':'Disabled' ?>
                </span>
            </div>
        </div>
        <div style="display:flex;gap:8px;margin-top:12px;">
            <button type="button" class="btn btn-primary btn-sm" onclick="testConnection()">
                <i class="fas fa-satellite-dish"></i> Test
            </button>
            <button type="submit" class="btn btn-success btn-sm">
                <i class="fas fa-floppy-disk"></i> Save
            </button>
        </div>
    </form>
</div>
</div><!-- right col -->

</div><!-- /two-col -->
</div><!-- /tab-settings -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 2: Nodes                                                           -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-nodes" class="tab-panel <?= $tab==='nodes'?'active':'' ?>">
<?php if (isset($_GET['lic_block'])): $__lv = nm_lic_can_add_nodes($conn, 0); ?>
<div style="background:rgba(240,169,44,.12);border:1px solid rgba(240,169,44,.45);color:#ffd98a;border-radius:10px;padding:12px 16px;margin-bottom:14px;font-size:13px;">
  <i class="fas fa-triangle-exclamation"></i>
  <b>NEURU is free &amp; open source.</b>
  Unlimited nodes, no limits — add as many as you like.
  Manage your free license in <a href="license.php" style="color:#ffe6ad;">Site Configuration → Licensing</a>.
</div>
<?php endif; ?>
<div class="two-col">

    <!-- Left: current nodes -->
    <div>
        <div class="glass-card">
            <h2><i class="fas fa-list-check"></i> Monitored Nodes</h2>

            <?php if (empty($nodes)): ?>
                <div style="text-align:center;color:#555;padding:30px;">
                    <i class="fas fa-server" style="font-size:32px;margin-bottom:10px;display:block;"></i>
                    No nodes configured yet. Browse LibreNMS and add nodes →
                </div>
            <?php else: ?>
                <!-- Node Administration: search + collapsible groups (ADDITIVE — filters the existing rows,
                     never changes the edit/interface/delete forms or their handlers). -->
                <div style="display:flex;gap:8px;align-items:center;margin:6px 0 10px;">
                    <div style="position:relative;flex:1;">
                        <i class="fas fa-search" style="position:absolute;left:11px;top:50%;transform:translateY(-50%);color:#5a6b85;font-size:12px;pointer-events:none;"></i>
                        <input id="nm-node-search" class="form-input" type="text" autocomplete="off" placeholder="Search nodes by name or IP…" oninput="nmApplyNodeFilter()" style="padding-left:32px;font-size:12px;">
                    </div>
                    <button type="button" class="btn btn-sm" onclick="nmGroupsAll(false)" title="Collapse all groups"><i class="fas fa-compress"></i></button>
                    <button type="button" class="btn btn-sm" onclick="nmGroupsAll(true)" title="Expand all groups"><i class="fas fa-expand"></i></button>
                    <span id="nm-node-count" style="font-size:11px;color:#889;white-space:nowrap;min-width:52px;text-align:right;"></span>
                </div>
                <div id="nm-node-nomatch" style="display:none;text-align:center;color:#667;padding:16px;font-size:12px;"><i class="fas fa-magnifying-glass"></i> No nodes match — try a different name or IP.</div>
                <style>
                  .nm-node-scroll{ max-height:62vh; overflow-y:auto; overflow-x:hidden; padding-right:6px; margin-right:-4px; }
                  .nm-node-scroll::-webkit-scrollbar{ width:8px; }
                  .nm-node-scroll::-webkit-scrollbar-thumb{ background:rgba(120,150,200,.28); border-radius:6px; }
                  .nm-node-scroll::-webkit-scrollbar-thumb:hover{ background:rgba(120,150,200,.5); }
                  .nm-node-scroll{ scrollbar-width:thin; scrollbar-color:rgba(120,150,200,.28) transparent; }
                </style>
                <div class="nm-node-scroll">
                <?php
                $grouped = [];
                foreach ($nodes as $n) {
                    $key = $n['grp_name'] ?? '— No Group —';
                    $grouped[$key][] = $n;
                }
                foreach ($grouped as $grp => $gnodes):
                    $color = $gnodes[0]['grp_color'] ?? '#4da3ff';
                ?>
                <div class="node-group-header nm-grp-h" onclick="nmToggleGroup(this)" style="cursor:pointer;user-select:none;">
                    <i class="fas fa-chevron-down nm-grp-chev" style="font-size:9px;color:#667;transition:transform .15s;width:10px;"></i>
                    <span style="width:10px;height:10px;border-radius:50%;background:<?= htmlspecialchars($color) ?>;display:inline-block;"></span>
                    <?= htmlspecialchars($grp) ?> <span class="nm-grp-count">(<?= count($gnodes) ?>)</span>
                </div>
                <?php
                // full FA class incl. family — linux/windows are BRAND icons (fab); solid ones = fas.
                // (Rendering a brand glyph with `fas` shows an empty box — that was the missing-icon bug.)
                $icon_map = ['routeros'=>'fas fa-dharmachakra','linux'=>'fab fa-linux','generic'=>'fas fa-server',
                             'windows'=>'fab fa-windows','cisco'=>'fas fa-network-wired','ping'=>'fas fa-satellite-dish',
                             'mikrotik'=>'fas fa-dharmachakra'];
                foreach ($gnodes as $nd):
                    $has_snmp = !empty($nd['snmp_community']);
                    $snmp_color  = $has_snmp ? 'var(--up)' : 'var(--warn)';
                    $snmp_bg     = $has_snmp ? 'rgba(46,204,113,.12)' : 'rgba(243,156,18,.12)';
                    $snmp_txt    = $has_snmp ? htmlspecialchars($nd['snmp_community']).' / '.($nd['snmp_version']?:'v2c') : 'no SNMP';
                    $icon_cls    = $icon_map[$nd['os_icon']??''] ?? 'fas fa-server';
                ?>
                <div class="nm-node" data-s="<?= htmlspecialchars(strtolower(trim(($nd['display_name']??'').' '.($nd['ip_address']??'').' '.($nd['snmp_community']??'')))) ?>">
                <div class="node-row">
                    <i class="<?= $icon_cls ?>" style="color:#4da3ff;font-size:13px;width:16px;text-align:center;"></i>
                    <div class="node-name"><?= htmlspecialchars($nd['display_name']) ?></div>
                    <div class="node-ip"><?= htmlspecialchars($nd['ip_address']??'—') ?></div>
                    <span style="font-size:10px;padding:2px 8px;border-radius:6px;background:<?= $snmp_bg ?>;color:<?= $snmp_color ?>;white-space:nowrap;">
                        <?= $snmp_txt ?>
                    </span>
                    <button class="btn btn-primary btn-sm" onclick="toggleEditForm(<?= $nd['id'] ?>)" title="Edit device">
                        <i class="fas fa-pen"></i>
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="showTab('interfaces');setIfaceNode(<?= $nd['id'] ?>)" title="Interfaces">
                        <i class="fas fa-ethernet"></i>
                    </button>
                    <form method="post" style="margin:0;" onsubmit="return confirm('Remove <?= htmlspecialchars(addslashes($nd['display_name'])) ?>?')">
                        <input type="hidden" name="action" value="del_node">
                        <input type="hidden" name="node_id" value="<?= $nd['id'] ?>">
                        <button type="submit" class="btn btn-danger btn-sm"><i class="fas fa-trash"></i></button>
                    </form>
                </div>
                <!-- Inline full-edit form -->
                <div id="edit-form-<?= $nd['id'] ?>" style="display:none;background:rgba(77,163,255,.04);border:1px solid rgba(77,163,255,.2);border-radius:8px;padding:14px;margin:4px 0 6px;">
                    <form method="post" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="edit_node">
                        <input type="hidden" name="node_id" value="<?= $nd['id'] ?>">
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px;">
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Display Name</label>
                                <input class="form-input" type="text" name="display_name" value="<?= htmlspecialchars($nd['display_name']) ?>" required style="font-size:12px;padding:6px 10px;">
                            </div>
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">IP Address</label>
                                <input class="form-input" type="text" name="ip_address" value="<?= htmlspecialchars($nd['ip_address']??'') ?>" placeholder="192.168.x.x" style="font-size:12px;padding:6px 10px;">
                            </div>
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Monitor Type</label>
                                <select class="form-select" name="monitor_type" style="font-size:12px;padding:6px 10px;">
                                    <option value="snmp" <?= (($nd['monitor_type']??'snmp')==='snmp')?'selected':'' ?>>SNMP (full metrics)</option>
                                    <option value="ping" <?= (($nd['monitor_type']??'')==='ping')?'selected':'' ?>>Ping only (ICMP)</option>
                                </select>
                            </div>
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">SNMP Community</label>
                                <input class="form-input" type="text" name="snmp_community" value="<?= htmlspecialchars($nd['snmp_community']??'') ?>" placeholder="public" style="font-size:12px;padding:6px 10px;">
                            </div>
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">SNMP Version</label>
                                <select class="form-select" name="snmp_version" style="font-size:12px;padding:6px 10px;">
                                    <option value="v1"  <?= ($nd['snmp_version']??'')==='v1' ?'selected':'' ?>>v1</option>
                                    <option value="v2c" <?= (($nd['snmp_version']??'')==='v2c'||empty($nd['snmp_version']))?'selected':'' ?>>v2c</option>
                                    <option value="v3"  <?= ($nd['snmp_version']??'')==='v3' ?'selected':'' ?>>v3</option>
                                </select>
                            </div>
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Subnet Mask</label>
                                <input class="form-input" type="text" name="subnet_mask" value="<?= htmlspecialchars($nd['subnet_mask']??'/24') ?>" placeholder="/24" style="font-size:12px;padding:6px 10px;">
                            </div>
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Device Icon</label>
                                <select class="form-select" name="os_icon" style="font-size:12px;padding:6px 10px;">
                                    <?php
                                        // Base choices + the poller's auto-detected value (mikrotik/juniper/…) so it's
                                        // ALWAYS present & preselected — otherwise an unlisted os_icon would silently
                                        // default to "generic" on save and drop the node out of Router Monitor.
                                        $iconOpts = ['generic'=>'Generic / Server','mikrotik'=>'MikroTik (RouterOS)','routeros'=>'MikroTik RouterOS','linux'=>'Linux','windows'=>'Windows','cisco'=>'Cisco'];
                                        $curIc = strtolower((string)($nd['os_icon'] ?? 'generic')) ?: 'generic';
                                        if (!isset($iconOpts[$curIc])) $iconOpts[$curIc] = ucfirst($curIc).' (detected)';
                                        foreach ($iconOpts as $v=>$l): ?>
                                    <option value="<?= $v ?>" <?= $curIc===$v?'selected':'' ?>><?= $l ?></option>
                                    <?php endforeach ?>
                                </select>
                            </div>
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Gateway Node <span style="color:#666;">(map link)</span></label>
                                <select class="form-select" name="gateway_node_id" style="font-size:12px;padding:6px 10px;">
                                    <option value="">— None —</option>
                                    <?php foreach ($nodes as $gn): if ($gn['id']===$nd['id']) continue; ?>
                                    <option value="<?= $gn['id'] ?>" <?= (int)($nd['gateway_node_id']??0)===(int)$gn['id']?'selected':'' ?>>
                                        <?= htmlspecialchars($gn['display_name']) ?> (<?= htmlspecialchars($gn['ip_address']??'') ?>)
                                    </option>
                                    <?php endforeach ?>
                                </select>
                            </div>
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Uplink Interface <span style="color:#666;">(to gateway)</span></label>
                                <select class="form-select" name="gateway_iface_id" style="font-size:12px;padding:6px 10px;">
                                    <option value="">— Auto —</option>
                                    <?php foreach ($node_ifaces[$nd['id']] ?? [] as $ifc): ?>
                                    <option value="<?= $ifc['id'] ?>" <?= (int)($nd['gateway_iface_id']??0)===(int)$ifc['id']?'selected':'' ?>>
                                        <?= htmlspecialchars($ifc['display_name'] ?: $ifc['if_name']) ?><?= $ifc['if_ip_address'] ? ' ('.htmlspecialchars($ifc['if_ip_address']).')' : '' ?>
                                    </option>
                                    <?php endforeach ?>
                                </select>
                            </div>
                            <div>
                                <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Group</label>
                                <select class="form-select" name="group_id" style="font-size:12px;padding:6px 10px;">
                                    <option value="">— No Group —</option>
                                    <?php foreach ($groups as $g): ?>
                                    <option value="<?= $g['id'] ?>" <?= (int)($nd['group_id']??0)===(int)$g['id']?'selected':'' ?>><?= htmlspecialchars($g['name']) ?></option>
                                    <?php endforeach ?>
                                </select>
                            </div>
                        </div>
                        <?php $curPhoto = nm_node_photo_url($nd); ?>
                        <div style="border-top:1px dashed rgba(77,163,255,.2);margin:4px 0 10px;padding-top:10px;">
                          <div style="font-size:10px;color:#4da3ff;text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px;"><i class="fas fa-box-archive"></i> Asset / Inventory <span style="color:#666;text-transform:none;">(model, serial, warranty — surfaced on Device Details)</span></div>
                          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
                            <div><label style="font-size:10px;color:#aaa;">Manufacturer</label><input class="form-input" type="text" name="manufacturer" value="<?= htmlspecialchars($nd['manufacturer']??'') ?>" placeholder="MikroTik" style="font-size:12px;padding:6px 10px;"></div>
                            <div><label style="font-size:10px;color:#aaa;">Model</label><input class="form-input" type="text" name="model" value="<?= htmlspecialchars($nd['model']??'') ?>" placeholder="CCR2004-1G-12S+2XS" style="font-size:12px;padding:6px 10px;"></div>
                            <div><label style="font-size:10px;color:#aaa;">Serial number</label><input class="form-input" type="text" name="serial_number" value="<?= htmlspecialchars($nd['serial_number']??'') ?>" style="font-size:12px;padding:6px 10px;"></div>
                            <div><label style="font-size:10px;color:#aaa;">Asset tag</label><input class="form-input" type="text" name="asset_tag" value="<?= htmlspecialchars($nd['asset_tag']??'') ?>" placeholder="NOC-00123" style="font-size:12px;padding:6px 10px;"></div>
                            <div><label style="font-size:10px;color:#aaa;">Purchase date</label><input class="form-input" type="date" name="purchase_date" value="<?= htmlspecialchars($nd['purchase_date']??'') ?>" style="font-size:12px;padding:6px 10px;"></div>
                            <div><label style="font-size:10px;color:#aaa;">Warranty expiry</label><input class="form-input" type="date" name="warranty_expiry" value="<?= htmlspecialchars($nd['warranty_expiry']??'') ?>" style="font-size:12px;padding:6px 10px;"></div>
                          </div>
                          <div style="margin-top:8px;"><label style="font-size:10px;color:#aaa;">Notes</label><textarea class="form-input" name="asset_notes" rows="2" style="font-size:12px;padding:6px 10px;width:100%;resize:vertical;" placeholder="Rack/location, support contract #, remarks…"><?= htmlspecialchars($nd['asset_notes']??'') ?></textarea></div>
                          <div style="display:flex;align-items:center;gap:14px;margin-top:8px;flex-wrap:wrap;">
                            <?php if ($curPhoto): ?><img src="<?= htmlspecialchars($curPhoto) ?>" alt="equipment" style="height:54px;border-radius:6px;border:1px solid rgba(77,163,255,.3);object-fit:cover;">
                            <label style="font-size:11px;color:#e0736b;cursor:pointer;"><input type="checkbox" name="remove_photo" value="1"> Remove photo</label><?php endif; ?>
                            <div><label style="font-size:10px;color:#aaa;display:block;margin-bottom:3px;"><i class="fas fa-camera"></i> Equipment photo <span style="color:#666;">(JPG/PNG/WebP)</span></label><input type="file" name="photo" accept="image/png,image/jpeg,image/gif,image/webp" style="font-size:11px;color:#ccc;"></div>
                          </div>
                        </div>
                        <?php $gE = $geoMap[$nd['id']] ?? null; ?>
                        <div style="border-top:1px dashed rgba(77,163,255,.2);margin:4px 0 10px;padding-top:10px;">
                          <div style="font-size:10px;color:#4da3ff;text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px;"><i class="fas fa-map-location-dot"></i> Map coordinates <span style="color:#666;text-transform:none;">(for the NOC Geo Wall — leave blank to remove)</span></div>
                          <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr auto;gap:8px;align-items:end;">
                            <div><label style="font-size:10px;color:#aaa;">Latitude</label><input class="form-input geo-lat" type="text" name="geo_lat" value="<?= $gE?htmlspecialchars($gE['lat']):'' ?>" placeholder="18.46" style="font-size:12px;padding:6px 10px;"></div>
                            <div><label style="font-size:10px;color:#aaa;">Longitude</label><input class="form-input geo-lon" type="text" name="geo_lon" value="<?= $gE?htmlspecialchars($gE['lon']):'' ?>" placeholder="-66.10" style="font-size:12px;padding:6px 10px;"></div>
                            <div><label style="font-size:10px;color:#aaa;">City</label><input class="form-input geo-city" type="text" name="geo_city" value="<?= $gE?htmlspecialchars($gE['city']??''):'' ?>" style="font-size:12px;padding:6px 10px;"></div>
                            <div><label style="font-size:10px;color:#aaa;">Country</label><input class="form-input geo-country" type="text" name="geo_country" value="<?= $gE?htmlspecialchars($gE['country']??''):'' ?>" style="font-size:12px;padding:6px 10px;"></div>
                            <div>
                              <label style="font-size:10px;color:#aaa;">Link</label>
                              <select class="form-select" name="geo_link_type" style="font-size:12px;padding:6px 10px;">
                                <?php foreach(['fiber','microwave','satellite','copper'] as $lt): ?><option value="<?= $lt ?>" <?= ($gE['link_type']??'fiber')===$lt?'selected':'' ?>><?= ucfirst($lt) ?></option><?php endforeach ?>
                              </select>
                            </div>
                          </div>
                          <button type="button" class="btn btn-sm" style="margin-top:8px;border-color:#2ecc71;color:#2ecc71;" onclick="pickOnMap(this)"><i class="fas fa-map-pin"></i> Pick on map</button>
                          <button type="button" class="btn btn-sm" style="margin-top:8px;border-color:#4da3ff;color:#4da3ff;" onclick="geoLocate(this,'<?= htmlspecialchars($nd['ip_address']??'') ?>')"><i class="fas fa-location-crosshairs"></i> Auto-locate from IP</button>
                          <span class="geo-msg" style="font-size:11px;margin-left:8px;"></span>
                        </div>
                        <div style="display:flex;gap:8px;">
                            <button type="submit" class="btn btn-success btn-sm"><i class="fas fa-save"></i> Save Changes</button>
                            <button type="button" class="btn btn-sm" style="border-color:#555;color:#888;" onclick="toggleEditForm(<?= $nd['id'] ?>)">Cancel</button>
                            <button type="button" class="btn btn-primary btn-sm" onclick="testSnmp('<?= htmlspecialchars($nd['ip_address']??'') ?>',this.closest('form').snmp_community.value,this.closest('form').snmp_version.value,<?= $nd['id'] ?>)">
                                <i class="fas fa-satellite-dish"></i> Test SNMP
                            </button>
                            <span id="snmp-test-<?= $nd['id'] ?>" style="font-size:11px;align-self:center;"></span>
                        </div>
                    </form>
                </div>
                </div>
                <?php endforeach ?>
                <?php endforeach ?>
                </div><!-- /.nm-node-scroll -->
            <?php endif ?>
        </div>

        <script>
        // ── Node Administration: client-side search + collapsible groups. PURELY ADDITIVE — it only
        //    shows/hides the already-rendered rows; it never touches the edit / interfaces / delete forms
        //    or their handlers. Group headers + node wrappers are flat siblings, so we walk siblings. ──
        function nmApplyNodeFilter(){
            const inp=document.getElementById('nm-node-search'); if(!inp) return;
            const q=(inp.value||'').trim().toLowerCase();
            let shown=0, total=0;
            document.querySelectorAll('.nm-grp-h').forEach(h=>{
                const collapsed = h.classList.contains('nm-collapsed') && !q;   // an active search overrides collapse
                let vis=0, tot=0, el=h.nextElementSibling;
                while(el && !el.classList.contains('nm-grp-h')){
                    if(el.classList.contains('nm-node')){
                        tot++; total++;
                        const hit = !q || (el.dataset.s||'').indexOf(q)>=0;
                        el.style.display = (hit && !collapsed) ? '' : 'none';
                        if(hit){ vis++; shown++; }
                    }
                    el=el.nextElementSibling;
                }
                const c=h.querySelector('.nm-grp-count'); if(c) c.textContent='('+(q? vis+'/'+tot : tot)+')';
                h.style.display = (q && vis===0) ? 'none' : '';
            });
            const cnt=document.getElementById('nm-node-count'); if(cnt) cnt.textContent = q ? (shown+' / '+total) : (total+(total===1?' node':' nodes'));
            const nm=document.getElementById('nm-node-nomatch'); if(nm) nm.style.display=(q && shown===0)?'':'none';
        }
        function nmToggleGroup(h){
            h.classList.toggle('nm-collapsed');
            const ch=h.querySelector('.nm-grp-chev'); if(ch) ch.style.transform = h.classList.contains('nm-collapsed')?'rotate(-90deg)':'';
            nmApplyNodeFilter();
        }
        function nmGroupsAll(expand){
            document.querySelectorAll('.nm-grp-h').forEach(h=>{
                h.classList.toggle('nm-collapsed', !expand);
                const ch=h.querySelector('.nm-grp-chev'); if(ch) ch.style.transform = expand?'':'rotate(-90deg)';
            });
            nmApplyNodeFilter();
        }
        document.addEventListener('DOMContentLoaded', ()=>{ if(document.getElementById('nm-node-search')) nmApplyNodeFilter(); });
        </script>

        <!-- Groups management -->
        <div class="glass-card">
            <h2><i class="fas fa-layer-group"></i> Node Groups</h2>
            <?php foreach ($groups as $g): ?>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                <span style="width:12px;height:12px;border-radius:50%;background:<?= htmlspecialchars($g['color']) ?>;display:inline-block;flex-shrink:0;"></span>
                <span style="flex:1;font-size:13px;"><?= htmlspecialchars($g['name']) ?></span>
                <form method="post" style="margin:0;" onsubmit="return confirm('Delete group? Nodes will be ungrouped.')">
                    <input type="hidden" name="action" value="del_group">
                    <input type="hidden" name="group_id" value="<?= $g['id'] ?>">
                    <button type="submit" class="btn btn-danger btn-sm"><i class="fas fa-trash"></i></button>
                </form>
            </div>
            <?php endforeach ?>
            <form method="post" style="margin-top:12px;">
                <input type="hidden" name="action" value="add_group">
                <div class="form-row-inline">
                    <input class="form-input" type="text" name="group_name" placeholder="New group name" style="flex:1;">
                    <input type="color" name="group_color" value="#4da3ff" style="height:38px;width:44px;border:none;background:none;cursor:pointer;border-radius:6px;">
                    <button type="submit" class="btn btn-success btn-sm"><i class="fas fa-plus"></i> Add</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Right: Add Device directly -->
    <div>
        <div class="glass-card">
            <h2><i class="fas fa-plus-circle"></i> Add Device</h2>
            <form method="post" id="add-node-form" enctype="multipart/form-data">
                <input type="hidden" name="action" value="add_node">
                <input type="hidden" name="device_id" value="0">
                <div class="form-row">
                    <label>Display Name *</label>
                    <input class="form-input" type="text" name="display_name" id="anf-display" placeholder="e.g. Core Router" required>
                </div>
                <div class="form-row">
                    <label>IP Address *</label>
                    <input class="form-input" type="text" name="ip_address" id="anf-ip" placeholder="192.168.x.x" required>
                </div>
                <div class="form-row">
                    <label>Monitor Type</label>
                    <select class="form-select" name="monitor_type" id="anf-mtype">
                        <option value="snmp" selected>SNMP — full metrics (CPU, memory, interfaces)</option>
                        <option value="ping">Ping only — ICMP reachability (up/down + latency)</option>
                    </select>
                </div>
                <div class="form-row">
                    <label>SNMP Community <span style="color:#666;font-size:10px;">(SNMP only)</span></label>
                    <input class="form-input" type="text" name="snmp_community" id="anf-comm" placeholder="public" value="public">
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                    <div class="form-row">
                        <label>SNMP Version</label>
                        <select class="form-select" name="snmp_version" id="anf-ver">
                            <option value="v1">v1</option>
                            <option value="v2c" selected>v2c</option>
                            <option value="v3">v3</option>
                        </select>
                    </div>
                    <div class="form-row">
                        <label>Device Icon</label>
                        <select class="form-select" name="os_icon" id="anf-icon">
                            <option value="generic" selected>Generic</option>
                            <option value="routeros">MikroTik RouterOS</option>
                            <option value="linux">Linux</option>
                            <option value="windows">Windows</option>
                            <option value="cisco">Cisco</option>
                        </select>
                    </div>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                    <div class="form-row">
                        <label>Subnet Mask</label>
                        <input class="form-input" type="text" name="subnet_mask" value="/24" placeholder="/24">
                    </div>
                    <div class="form-row">
                        <label>Group</label>
                        <select class="form-select" name="group_id">
                            <option value="">— No Group —</option>
                            <?php foreach ($groups as $g): ?>
                            <option value="<?= $g['id'] ?>"><?= htmlspecialchars($g['name']) ?></option>
                            <?php endforeach ?>
                        </select>
                    </div>
                </div>
                <details style="margin-top:12px;border:1px solid rgba(77,163,255,.18);border-radius:8px;padding:8px 10px;">
                    <summary style="cursor:pointer;font-size:12px;color:#4da3ff;"><i class="fas fa-box-archive"></i> Asset / Inventory &amp; photo <span style="color:#666;">(optional)</span></summary>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px;">
                        <div class="form-row"><label>Manufacturer</label><input class="form-input" type="text" name="manufacturer" placeholder="MikroTik"></div>
                        <div class="form-row"><label>Model</label><input class="form-input" type="text" name="model" placeholder="CCR2004-1G-12S+2XS"></div>
                        <div class="form-row"><label>Serial number</label><input class="form-input" type="text" name="serial_number"></div>
                        <div class="form-row"><label>Asset tag</label><input class="form-input" type="text" name="asset_tag" placeholder="NOC-00123"></div>
                        <div class="form-row"><label>Purchase date</label><input class="form-input" type="date" name="purchase_date"></div>
                        <div class="form-row"><label>Warranty expiry</label><input class="form-input" type="date" name="warranty_expiry"></div>
                    </div>
                    <div class="form-row"><label>Notes</label><textarea class="form-input" name="asset_notes" rows="2" placeholder="Rack/location, support contract #, remarks…"></textarea></div>
                    <div class="form-row"><label><i class="fas fa-camera"></i> Equipment photo <span style="color:#666;font-size:10px;">(JPG/PNG/WebP, ≤8 MB)</span></label><input type="file" name="photo" accept="image/png,image/jpeg,image/gif,image/webp" style="color:#ccc;"></div>
                </details>
                <div style="display:flex;gap:8px;margin-top:12px;align-items:center;flex-wrap:wrap;">
                    <button type="button" class="btn btn-primary btn-sm" onclick="testSnmpNew()">
                        <i class="fas fa-satellite-dish"></i> Test SNMP
                    </button>
                    <span id="snmp-test-new" style="font-size:11px;"></span>
                </div>
                <div style="display:flex;gap:10px;margin-top:14px;">
                    <button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> Add Device</button>
                </div>
            </form>
        </div>

        <?php if ($_lnms_cfg['enabled']): ?>
        <!-- LibreNMS Browser (legacy) -->
        <div class="glass-card" style="border-color:rgba(243,156,18,.25);">
            <h2 style="color:var(--warn);font-size:13px;"><i class="fas fa-cloud-download-alt"></i> Import from LibreNMS (Legacy)</h2>
            <button class="btn btn-sm" style="border-color:var(--warn);color:var(--warn);" onclick="browseDevices()" id="browse-btn">
                <i class="fas fa-satellite-dish"></i> Browse LibreNMS
            </button>
            <div id="browse-status" style="font-size:12px;color:#888;margin-top:8px;display:none;"></div>
            <div id="device-browser" style="margin-top:12px;display:none;">
                <div class="search-wrap">
                    <i class="fas fa-search"></i>
                    <input type="text" id="dev-search" placeholder="Filter…" oninput="filterDevices()">
                </div>
                <div style="max-height:280px;overflow-y:auto;">
                    <table class="dev-table" id="dev-table">
                        <thead><tr><th>Device</th><th>IP</th><th>OS</th><th></th></tr></thead>
                        <tbody id="dev-tbody"></tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php endif ?>
    </div>

</div><!-- /two-col -->
</div><!-- /tab-nodes -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 3: Interfaces                                                      -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-interfaces" class="tab-panel <?= $tab==='interfaces'?'active':'' ?>">
<div class="glass-card">
    <h2><i class="fas fa-ethernet"></i> Interface Management</h2>

    <?php if (empty($nodes)): ?>
    <div style="text-align:center;color:#555;padding:30px;">
        <i class="fas fa-server" style="font-size:28px;margin-bottom:10px;display:block;"></i>
        Add nodes first in the <strong>Nodes</strong> tab, then manage interfaces here.
    </div>
    <?php else: ?>

    <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;flex-wrap:wrap;">
        <label style="font-size:12px;color:#888;text-transform:uppercase;letter-spacing:.8px;">Node</label>
        <select class="form-select" id="iface-node-sel" onchange="loadNodeIfacesDirect()" style="max-width:300px;">
            <?php foreach ($nodes as $nd): ?>
            <option value="<?= $nd['id'] ?>" <?= (int)$nd['id']===$iface_node_id?'selected':'' ?>>
                <?= htmlspecialchars($nd['display_name']) ?> (<?= htmlspecialchars($nd['ip_address']??'—') ?>)
            </option>
            <?php endforeach ?>
        </select>
        <button class="btn btn-primary btn-sm" onclick="discoverIfaces()">
            <i class="fas fa-radar"></i> Discover via SNMP
        </button>
        <button class="btn btn-sm" style="border-color:#555;color:#888;" onclick="loadNodeIfacesDirect()">
            <i class="fas fa-sync-alt"></i> Refresh
        </button>
        <div id="iface-status" style="font-size:12px;color:#888;"></div>
    </div>

    <div id="iface-content">
        <div style="color:#888;font-size:13px;padding:20px 0;text-align:center;">
            <span class="spinner"></span>&nbsp; Loading…
        </div>
    </div>
    <input type="hidden" id="iface-node-id" value="<?= $iface_node_id ?>">

    <?php endif ?>
</div>
</div><!-- /tab-interfaces -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 4: Poller                                                          -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<?php
// Load poller config and recent log
$poll_cfg = [];
if ($conn->query("SHOW TABLES LIKE 'nm_poller_config'")->num_rows > 0) {
    $pc_res = $conn->query("SELECT cfg_key, cfg_value FROM nm_poller_config");
    while ($r = $pc_res->fetch_assoc()) $poll_cfg[$r['cfg_key']] = $r['cfg_value'];
}
$poll_interval  = $poll_cfg['interval_minutes'] ?? '5';
$poll_retention = $poll_cfg['retention_days']   ?? '30';
$poll_log = [];
if ($conn->query("SHOW TABLES LIKE 'nm_poller_log'")->num_rows > 0) {
    $pl_res = $conn->query("SELECT * FROM nm_poller_log ORDER BY ran_at DESC LIMIT 15");
    $poll_log = $pl_res ? $pl_res->fetch_all(MYSQLI_ASSOC) : [];
}
// Save poller config
if ($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='save_poller') {
    $int = max(1, min(60, (int)($_POST['interval_minutes']??5)));
    $ret = max(1, min(365,(int)($_POST['retention_days']??30)));
    $conn->query("CREATE TABLE IF NOT EXISTS nm_poller_config(
        id INT AUTO_INCREMENT PRIMARY KEY, cfg_key VARCHAR(100) NOT NULL UNIQUE,
        cfg_value VARCHAR(500) NOT NULL DEFAULT '', updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $conn->query("INSERT INTO nm_poller_config(cfg_key,cfg_value) VALUES('interval_minutes','$int')
                  ON DUPLICATE KEY UPDATE cfg_value='$int'");
    $conn->query("INSERT INTO nm_poller_config(cfg_key,cfg_value) VALUES('retention_days','$ret')
                  ON DUPLICATE KEY UPDATE cfg_value='$ret'");
    header('Location: net_mon_config.php?tab=poller&saved=1'); exit;
}
?>
<!-- ─── Connections (manual topology wiring) ──────────────────────────────── -->
<div id="tab-links" class="tab-panel <?= $tab==='links'?'active':'' ?>">
    <script>window._LK_NODES = <?= json_encode(array_map(fn($n)=>['id'=>(int)$n['id'],'name'=>$n['display_name'],'ip'=>$n['ip_address']], $nodes)) ?>;</script>

    <div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:16px 18px;margin-bottom:14px;">
        <h2 style="margin-top:0;"><i class="fas fa-diagram-project" style="color:var(--accent);"></i> Connections</h2>
        <p style="color:#8a909a;font-size:12.5px;margin:0 0 14px;">
            Wire devices together explicitly — pick the interface on each end and which side's traffic the link shows.
            Auto-mapping keeps running; these connections take precedence where defined.
        </p>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;align-items:end;">
            <div><label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Device A</label>
                <select class="form-select" id="lk-a-node" onchange="lkLoadIf('a')" style="font-size:12px;padding:6px 10px;width:100%;"></select></div>
            <div><label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Interface A</label>
                <select class="form-select" id="lk-a-if" style="font-size:12px;padding:6px 10px;width:100%;"><option value="">— whole device —</option></select></div>
            <div><label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Device Z</label>
                <select class="form-select" id="lk-z-node" onchange="lkLoadIf('z')" style="font-size:12px;padding:6px 10px;width:100%;"></select></div>
            <div><label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Interface Z</label>
                <select class="form-select" id="lk-z-if" style="font-size:12px;padding:6px 10px;width:100%;"><option value="">— whole device —</option></select></div>
            <div><label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Traffic from</label>
                <select class="form-select" id="lk-side" style="font-size:12px;padding:6px 10px;width:100%;"><option value="z">Z interface</option><option value="a">A interface</option></select></div>
            <div><label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Label (optional)</label>
                <input class="form-input" id="lk-label" placeholder="e.g. WiFi uplink" style="font-size:12px;padding:6px 10px;width:100%;"></div>
            <div><button class="btn btn-success" onclick="saveLink()" style="white-space:nowrap;"><i class="fas fa-plus"></i> Add Connection</button></div>
        </div>
        <div style="overflow-x:auto;margin-top:14px;">
            <table class="cfg-table" style="width:100%;font-size:12.5px;border-collapse:collapse;">
                <thead><tr style="color:#7c828c;font-size:10.5px;text-transform:uppercase;">
                    <th style="text-align:left;padding:6px 8px;">A (device · interface)</th>
                    <th style="text-align:center;padding:6px 8px;"></th>
                    <th style="text-align:left;padding:6px 8px;">Z (device · interface)</th>
                    <th style="text-align:left;padding:6px 8px;">Traffic</th>
                    <th style="text-align:left;padding:6px 8px;">Label</th>
                    <th></th>
                </tr></thead>
                <tbody id="lk-tbody"><tr><td colspan="6" style="color:#777;padding:14px;text-align:center;">Loading…</td></tr></tbody>
            </table>
        </div>
    </div>

    <!-- Auto-discovered connections — remove the ones you don't want -->
    <div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:16px 18px;margin-bottom:14px;">
        <h2 style="margin-top:0;"><i class="fas fa-wand-magic-sparkles" style="color:var(--accent);"></i> Auto-discovered connections
            <button class="btn btn-sm" onclick="loadAutoLinks()" style="float:right;font-size:11px;"><i class="fas fa-rotate"></i> Refresh</button></h2>
        <p style="color:#8a909a;font-size:12.5px;margin:0 0 12px;">
            These links are inferred automatically from each device's subnet/gateway. Remove any that are wrong —
            removed links stay hidden even after re-polling. A custom connection above always overrides the auto guess.
        </p>
        <div style="overflow-x:auto;">
            <table class="cfg-table" style="width:100%;font-size:12.5px;border-collapse:collapse;">
                <thead><tr style="color:#7c828c;font-size:10.5px;text-transform:uppercase;">
                    <th style="text-align:left;padding:6px 8px;">A (device · interface)</th>
                    <th style="text-align:center;padding:6px 8px;"></th>
                    <th style="text-align:left;padding:6px 8px;">Z (device · interface)</th>
                    <th style="text-align:left;padding:6px 8px;">Type</th>
                    <th style="text-align:left;padding:6px 8px;">Traffic</th>
                    <th></th>
                </tr></thead>
                <tbody id="auto-tbody"><tr><td colspan="6" style="color:#777;padding:14px;text-align:center;">Loading…</td></tr></tbody>
            </table>
        </div>
        <div id="hidden-wrap" style="margin-top:12px;display:none;">
            <div style="font-size:10.5px;color:#7c828c;text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px;">
                <i class="fas fa-eye-slash"></i> Removed (hidden) connections</div>
            <div id="hidden-list" style="display:flex;flex-wrap:wrap;gap:8px;"></div>
        </div>
    </div>

    <div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:16px 18px;">
        <h2 style="margin-top:0;"><i class="fas fa-plus-circle" style="color:var(--accent);"></i> Virtual (dummy) interface</h2>
        <p style="color:#8a909a;font-size:12.5px;margin:0 0 12px;">
            For a device that doesn't expose an interface over SNMP (e.g. an AP's radio) — create a named virtual
            interface so you can wire connections to it. It carries no traffic itself; pick the other end's interface for traffic.
        </p>
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:end;">
            <div><label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Device</label>
                <select class="form-select" id="dmy-node" style="font-size:12px;padding:6px 10px;min-width:200px;"></select></div>
            <div><label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:3px;">Interface name</label>
                <input class="form-input" id="dmy-name" placeholder="e.g. wlan0, radio0" style="font-size:12px;padding:6px 10px;"></div>
            <div><button class="btn btn-primary" onclick="addDummy()"><i class="fas fa-plus"></i> Add Virtual Interface</button></div>
            <span id="dmy-msg" style="font-size:11px;color:#2ecc71;"></span>
        </div>
    </div>
</div>

<div id="tab-poller" class="tab-panel <?= $tab==='poller'?'active':'' ?>">
<div class="section-wrap" style="display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start;">

<!-- Poller Config -->
<div class="glass-card">
    <h3 style="margin:0 0 16px;font-size:14px;color:var(--accent);display:flex;align-items:center;gap:8px;">
        <i class="fas fa-clock-rotate-left"></i> Poller Configuration
    </h3>
    <?php if ($saved && $tab==='poller'): ?>
    <div class="alert-ok" style="margin-bottom:12px;"><i class="fas fa-check"></i> Poller config saved.</div>
    <?php endif ?>
    <form method="post">
        <input type="hidden" name="action" value="save_poller">
        <div style="display:flex;flex-direction:column;gap:14px;">
            <div>
                <label class="form-label">Poll Interval (minutes)</label>
                <select name="interval_minutes" class="form-select">
                    <?php foreach ([1,2,5,10,15,30,60] as $m): ?>
                    <option value="<?= $m ?>" <?= $poll_interval==$m?'selected':'' ?>><?= $m ?> minute<?= $m>1?'s':'' ?></option>
                    <?php endforeach ?>
                </select>
                <div style="font-size:11px;color:#555;margin-top:4px;">How often the poller collects data from LibreNMS.</div>
            </div>
            <div>
                <label class="form-label">Data Retention (days)</label>
                <select name="retention_days" class="form-select">
                    <?php foreach ([7=>['7 days','~1 week'],30=>['30 days','~1 month'],90=>['90 days','~3 months'],180=>['180 days','~6 months'],365=>['365 days','1 year']] as $d=>$l): ?>
                    <option value="<?= $d ?>" <?= $poll_retention==$d?'selected':'' ?>><?= $l[0] ?> (<?= $l[1] ?>)</option>
                    <?php endforeach ?>
                </select>
                <div style="font-size:11px;color:#555;margin-top:4px;">Older data is automatically pruned each poll cycle.</div>
            </div>
            <button type="submit" class="btn btn-primary" style="align-self:flex-start;">
                <i class="fas fa-floppy-disk"></i> Save Poller Config
            </button>
        </div>
    </form>
</div>

<!-- Cron Setup -->
<div class="glass-card">
    <h3 style="margin:0 0 16px;font-size:14px;color:var(--accent);display:flex;align-items:center;gap:8px;">
        <i class="fas fa-terminal"></i> Cron Job Setup
    </h3>
    <p style="font-size:12px;color:#888;margin:0 0 12px;">
        Add this line to your crontab (<code>crontab -e</code>) to run the poller automatically.
        Adjust the interval to match the setting above.
    </p>
    <div style="background:rgba(0,0,0,.5);border:1px solid #333;border-radius:8px;padding:12px 16px;margin-bottom:12px;">
        <code style="font-size:11px;color:#4da3ff;word-break:break-all;">
            */<span id="cron-interval"><?= $poll_interval ?></span> * * * * <?= VENV_PYTHON ?> <?= SCRIPTS_DIR ?>/nm_poller.py >> <?= LOG_DIR ?>/nm_poller.log 2>&1
        </code>
    </div>
    <p style="font-size:12px;color:#888;margin:0 0 12px;">Or run it manually right now:</p>
    <div style="background:rgba(0,0,0,.5);border:1px solid #333;border-radius:8px;padding:12px 16px;margin-bottom:16px;">
        <code style="font-size:11px;color:#2ecc71;">
            <?= VENV_PYTHON ?> <?= SCRIPTS_DIR ?>/nm_poller.py
        </code>
    </div>
    <div style="display:flex;gap:10px;">
        <a href="net_mon_stats.php" class="btn btn-primary btn-sm">
            <i class="fas fa-chart-area"></i> Open Statistics
        </a>
        <button class="btn btn-sm" onclick="testPoller()">
            <i class="fas fa-play"></i> Test Run (AJAX)
        </button>
    </div>
    <div id="poller-test-out" style="margin-top:12px;display:none;background:rgba(0,0,0,.5);border:1px solid #333;
         border-radius:8px;padding:12px;font-size:11px;color:#2ecc71;font-family:monospace;max-height:150px;overflow-y:auto;"></div>
</div>

</div><!-- /2-col -->

<!-- Recent Poller Log -->
<?php if ($poll_log): ?>
<div class="glass-card" style="margin-top:20px;">
    <h3 style="margin:0 0 14px;font-size:14px;color:var(--accent);"><i class="fas fa-list"></i> Recent Poll History</h3>
    <table style="width:100%;border-collapse:collapse;font-size:12px;">
        <thead><tr>
            <?php foreach (['Time','Duration','Nodes','Ports','Errors','Status'] as $h): ?>
            <th style="color:#555;font-size:10px;text-transform:uppercase;letter-spacing:1px;padding:5px 10px;text-align:left;border-bottom:1px solid var(--border);"><?= $h ?></th>
            <?php endforeach ?>
        </tr></thead>
        <tbody>
        <?php foreach ($poll_log as $pl): ?>
        <tr style="border-bottom:1px solid rgba(255,255,255,.04);">
            <td style="padding:6px 10px;color:#aaa;"><?= $pl['ran_at'] ?></td>
            <td style="padding:6px 10px;color:#888;"><?= $pl['duration_ms'] ?>ms</td>
            <td style="padding:6px 10px;color:#888;"><?= $pl['nodes_polled'] ?></td>
            <td style="padding:6px 10px;color:#888;"><?= $pl['ports_polled'] ?></td>
            <td style="padding:6px 10px;color:<?= $pl['errors']>0?'#e74c3c':'#555' ?>;"><?= $pl['errors'] ?></td>
            <td style="padding:6px 10px;">
                <span style="background:<?= $pl['status']==='ok'?'rgba(46,204,113,.2)':'rgba(243,156,18,.2)' ?>;
                             color:<?= $pl['status']==='ok'?'#2ecc71':'#f39c12' ?>;
                             padding:2px 8px;border-radius:10px;font-size:10px;"><?= htmlspecialchars($pl['status']) ?></span>
            </td>
        </tr>
        <?php endforeach ?>
        </tbody>
    </table>
</div>
<?php else: ?>
<div class="glass-card" style="margin-top:20px;text-align:center;padding:30px;color:#555;">
    <i class="fas fa-history" style="font-size:28px;margin-bottom:10px;display:block;"></i>
    No poll history yet. Run the poller script to start collecting data.
</div>
<?php endif ?>

</div><!-- /tab-poller -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 5: SNMP OIDs                                                       -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-snmp" class="tab-panel <?= $tab==='snmp'?'active':'' ?>">

<div class="snmp-intro">
    <div class="snmp-intro-head">
        <i class="fas fa-circle-question"></i><b>What is this page, in plain words?</b><br>
        <span>SNMP is how NEURU reads health numbers (CPU, RAM, temperature…) from a device over the network. An <b style="color:#cfe4ff;">OID</b> is simply the <b style="color:#cfe4ff;">address of one number</b> inside the device — e.g. "current CPU load". You rarely need to touch this page; here's the whole model in 3 steps:</span>
    </div>
    <div class="snmp-steps">
        <div class="snmp-step"><span class="snmp-step-n">1</span><div>
            <b>CPU / RAM / Disk — already automatic</b>
            <p>The moment a device has an <b>SNMP community</b> (set it in the <b>Nodes</b> tab), NEURU collects CPU, memory and disk for you. Nothing to configure here for those.</p>
        </div></div>
        <div class="snmp-step"><span class="snmp-step-n">2</span><div>
            <b>Want extra sensors? Use a Template</b>
            <p>Temperatures, fan speed and vendor metrics live at special OIDs. Pick the <b>Template</b> that matches your gear (MikroTik / Linux / Cisco…) and <b>assign it to the device</b> in the right-hand panel.</p>
        </div></div>
        <div class="snmp-step"><span class="snmp-step-n">3</span><div>
            <b>Need one specific value? Add a custom OID</b>
            <p>For a one-off metric, paste a single OID from the vendor's MIB onto one device and name it. This is the <b>Advanced</b> bit at the bottom-right.</p>
        </div></div>
    </div>
</div>

<div class="snmp-3col">

<!-- ── Column 1: Template Library ── -->
<div>
    <div class="glass-card">
        <h2><span class="snmp-sec-tag">A</span> Sensor Templates</h2>
        <p style="font-size:11.5px;color:#9aa;margin:0 0 10px;line-height:1.5;">A template is a <b style="color:#cfe4ff;">reusable bundle of extra OIDs</b> for a vendor. Click one to see what it reads, then assign it in panel <b style="color:var(--accent);">C →</b></p>

        <input type="text" class="tpl-filter" id="tplFilter" placeholder="🔍  Filter templates by name or vendor…" oninput="filterTemplates()">

        <div class="tpl-list" id="tplList">
        <?php foreach ($oid_templates as $tpl):
            $os = strtolower((string)$tpl['os_type']);
            $ic = ['cisco'=>'fa-network-wired','mikrotik'=>'fa-wifi','linux'=>'fa-linux','windows'=>'fa-windows','printer'=>'fa-print','generic'=>'fa-microchip'][$os] ?? 'fa-server';
            $br = in_array($os, ['linux','windows'], true) ? 'fa-brands' : 'fa-solid';
        ?>
        <div class="tpl-card" id="tplcard-<?= $tpl['id'] ?>" data-search="<?= htmlspecialchars(strtolower($tpl['name'].' '.$tpl['os_type'])) ?>" onclick="previewTemplate(<?= $tpl['id'] ?>)">
            <div class="tpl-ico"><i class="<?= $br ?> <?= $ic ?>"></i></div>
            <div class="tpl-body">
                <div class="tpl-name">
                    <?= htmlspecialchars($tpl['name']) ?>
                    <span class="<?= $tpl['is_builtin']?'builtin-badge':'custom-badge' ?>"><?= $tpl['is_builtin']?'built-in':'custom' ?></span>
                </div>
                <div class="tpl-meta"><?= htmlspecialchars($tpl['os_type']) ?> · <?= $tpl['oid_count'] ?> OID<?= $tpl['oid_count']!=1?'s':'' ?></div>
                <?php if ($tpl['description']): ?><div class="tpl-desc"><?= htmlspecialchars($tpl['description']) ?></div><?php endif ?>
                <?php if (!$tpl['is_builtin']): ?>
                <form method="post" style="margin-top:6px;" onclick="event.stopPropagation();" onsubmit="return confirm('Delete this template and all its OIDs?')">
                    <input type="hidden" name="action" value="del_custom_tpl">
                    <input type="hidden" name="tpl_id" value="<?= $tpl['id'] ?>">
                    <button type="submit" class="btn btn-danger btn-sm" style="padding:2px 8px;font-size:10.5px;"><i class="fas fa-trash"></i> Delete</button>
                </form>
                <?php endif ?>
            </div>
        </div>
        <?php endforeach ?>
        <div class="tpl-empty" id="tplEmpty">No templates match your filter.</div>
        </div>

        <!-- Add custom template (collapsible) -->
        <div class="tpl-collapse-hd" onclick="toggleCreateTpl()">
            <span><i class="fas fa-plus-circle" style="color:var(--accent);"></i> Create custom template</span>
            <i class="fas fa-chevron-down" id="tplCreateChevron" style="font-size:11px;transition:.2s;"></i>
        </div>
        <div id="tplCreateForm" style="display:none;padding-top:11px;">
            <form method="post">
                <input type="hidden" name="action" value="add_custom_tpl">
                <div style="display:flex;flex-direction:column;gap:8px;">
                    <input class="form-input form-mini" type="text" name="tpl_name" placeholder="Template name" required style="font-size:12px;padding:7px 10px;">
                    <select class="form-select" name="tpl_os" style="font-size:12px;padding:7px 10px;">
                        <option value="generic">Generic</option>
                        <option value="mikrotik">MikroTik</option>
                        <option value="linux">Linux</option>
                        <option value="cisco">Cisco</option>
                        <option value="windows">Windows</option>
                        <option value="other">Other</option>
                    </select>
                    <textarea class="form-input" name="tpl_desc" rows="2" placeholder="Description (optional)" style="resize:none;font-size:11px;padding:7px 10px;"></textarea>
                    <button type="submit" class="btn btn-success btn-sm"><i class="fas fa-plus"></i> Create Template</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- ── Column 2: Template OID Preview ── -->
<div>
    <div class="glass-card" id="tpl-preview-card">
        <h2><span class="snmp-sec-tag">B</span> What this template reads <span id="tpl-preview-title" style="color:#9aa;font-weight:400;font-size:13px;margin-left:6px;"></span></h2>
        <div id="tpl-preview-content" style="color:#666;font-size:12px;text-align:center;padding:30px;">
            <i class="fas fa-hand-pointer" style="font-size:24px;margin-bottom:8px;display:block;color:var(--accent);"></i>
            Click a template in panel <b style="color:var(--accent);">A</b> to see the list of values it collects.
        </div>
    </div>

    <!-- Add custom OID to template (only shown for custom templates) -->
    <div class="glass-card" id="tpl-add-oid-card" style="display:none;">
        <h2><i class="fas fa-plus-circle"></i> Add OID to Template</h2>
        <div id="tpl-add-oid-form"></div>
    </div>
</div>

<!-- ── Column 3: Per-Node SNMP Configuration ── -->
<div>
    <div class="glass-card">
        <h2><span class="snmp-sec-tag">C</span> Apply to a Device</h2>

        <?php if (empty($nodes)): ?>
        <div style="color:#555;font-size:12px;text-align:center;padding:20px;">
            <i class="fas fa-server" style="font-size:24px;display:block;margin-bottom:8px;"></i>
            Add nodes first in the Nodes tab.
        </div>
        <?php else: ?>

        <div style="margin-bottom:12px;">
            <label style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.7px;">1. Pick the device</label>
            <select class="form-select" id="oid-node-sel" onchange="loadNodeOids()" style="margin-top:5px;">
                <?php foreach ($nodes as $nd): ?>
                <option value="<?= $nd['id'] ?>" data-tplid="<?= $nd['oid_template_id'] ?? '' ?>">
                    <?= htmlspecialchars($nd['display_name']) ?> (<?= htmlspecialchars($nd['ip_address']??'?') ?>)
                </option>
                <?php endforeach ?>
            </select>
        </div>

        <!-- Template assignment for this node -->
        <div style="margin-bottom:14px;padding:10px 12px;background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:8px;">
            <label style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.7px;display:block;margin-bottom:6px;">
                <i class="fas fa-code-branch" style="color:var(--accent);"></i> 2. Choose its sensor template
            </label>
            <div style="display:flex;gap:8px;align-items:center;">
                <select class="form-select" id="node-tpl-sel" style="flex:1;font-size:12px;padding:7px 10px;">
                    <option value="">— None (just CPU / RAM / Disk) —</option>
                    <?php foreach ($oid_templates as $t): ?>
                    <option value="<?= $t['id'] ?>"><?= htmlspecialchars($t['name']) ?></option>
                    <?php endforeach ?>
                </select>
                <button class="btn btn-primary btn-sm" onclick="saveNodeTemplate()">
                    <i class="fas fa-check"></i> Save
                </button>
            </div>
            <div class="fhelp">
                <i class="fas fa-info-circle"></i>
                CPU, memory and disk are always collected automatically — you only pick a template here to add <b style="color:#9fb8d6;">extra</b> sensors (e.g. temperature). Pick “None” if you just want the basics.
            </div>
        </div>

        <!-- Custom OIDs for this node -->
        <div>
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                <label style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.7px;">
                    <i class="fas fa-list"></i> Custom OIDs on this device <span class="adv-tag">Advanced</span>
                </label>
                <button class="btn btn-primary btn-sm" onclick="toggleAddOidForm()">
                    <i class="fas fa-plus"></i> Add OID
                </button>
            </div>
            <div class="fhelp" style="margin:-2px 0 8px;">Only needed for a value no template covers. You'll paste the OID straight from the vendor's MIB/datasheet.</div>

            <div id="node-oid-list" style="margin-bottom:10px;">
                <div style="color:#555;font-size:12px;text-align:center;padding:15px;">
                    <span class="spinner"></span> Loading…
                </div>
            </div>

            <!-- Inline add OID form -->
            <div id="add-oid-form" style="display:none;background:rgba(77,163,255,.05);border:1px solid rgba(77,163,255,.2);border-radius:8px;padding:14px;">
                <div style="font-size:12px;font-weight:600;color:var(--accent);margin-bottom:4px;">
                    <i class="fas fa-plus"></i> Add a custom OID
                </div>
                <div class="fhelp" style="margin-bottom:10px;">Fill the two required fields (★). The rest have sensible defaults — leave them alone unless you know you need them.</div>
                <div style="display:flex;flex-direction:column;gap:8px;">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                        <div>
                            <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.6px;">Name <span style="color:#f39c12;">★</span></label>
                            <input class="form-input" type="text" id="new-mname" placeholder="e.g. CPU Temp" style="font-size:12px;padding:6px 10px;margin-top:3px;">
                            <div class="fhelp">Label shown on charts.</div>
                        </div>
                        <div>
                            <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.6px;">Category</label>
                            <select class="form-select" id="new-mtype" style="font-size:12px;padding:6px 10px;margin-top:3px;">
                                <option value="cpu">CPU</option>
                                <option value="memory">Memory</option>
                                <option value="disk">Disk</option>
                                <option value="temperature">Temperature</option>
                                <option value="custom" selected>Custom</option>
                            </select>
                        </div>
                    </div>
                    <div>
                        <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.6px;">OID <span style="color:#f39c12;">★</span></label>
                        <input class="form-input" type="text" id="new-oid" placeholder=".1.3.6.1.2.1.25.3.3.1.2" style="font-family:monospace;font-size:12px;padding:6px 10px;margin-top:3px;">
                        <div class="fhelp">The address of the value — copy it from the vendor's MIB or datasheet.</div>
                    </div>
                    <div>
                        <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.6px;">Total OID <span style="color:#666;text-transform:none;">(optional)</span></label>
                        <input class="form-input" type="text" id="new-oid-total" placeholder="leave blank for a direct value" style="font-family:monospace;font-size:12px;padding:6px 10px;margin-top:3px;">
                        <div class="fhelp">Only if you want a percentage: NEURU computes value ÷ total × 100 (e.g. used ÷ capacity).</div>
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 1fr 1.3fr;gap:8px;">
                        <div>
                            <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.6px;">Unit</label>
                            <input class="form-input" type="text" id="new-unit" value="%" style="font-size:12px;padding:6px 10px;margin-top:3px;">
                            <div class="fhelp">e.g. %, °C, MB</div>
                        </div>
                        <div>
                            <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.6px;">Scale</label>
                            <input class="form-input" type="number" id="new-scale" value="1.0" step="0.001" style="font-size:12px;padding:6px 10px;margin-top:3px;">
                            <div class="fhelp">Multiplier (use 0.1 if the device reports tenths).</div>
                        </div>
                        <div>
                            <label style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.6px;">Read mode</label>
                            <select class="form-select" id="new-walk" style="font-size:12px;padding:6px 10px;margin-top:3px;">
                                <option value="0">Single value (snmpget)</option>
                                <option value="1">Subtree (snmpwalk)</option>
                            </select>
                            <div class="fhelp">Leave on “Single value” unless the OID is a table.</div>
                        </div>
                    </div>
                    <div style="display:flex;gap:8px;margin-top:4px;">
                        <button class="btn btn-success btn-sm" onclick="addNodeOid()"><i class="fas fa-plus"></i> Add</button>
                        <button class="btn btn-sm" style="border-color:#555;color:#888;" onclick="toggleAddOidForm()"><i class="fas fa-times"></i> Cancel</button>
                    </div>
                    <div id="add-oid-status" style="font-size:11px;"></div>
                </div>
            </div>
        </div>

        <?php endif ?>
    </div>
</div>

</div><!-- /snmp-3col -->
</div><!-- /tab-snmp -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB 6: Discovery                                                        -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-discovery" class="tab-panel <?= $tab==='discovery'?'active':'' ?>">
<div class="two-col">

<!-- Left: Control -->
<div>
<div class="glass-card">
    <h2><i class="fas fa-radar"></i> LAN Auto-Discovery</h2>
    <p style="font-size:12px;color:#888;line-height:1.7;margin:0 0 16px;">
        Ping-sweeps configured subnets and SNMP-probes every live host.
        Results appear as <strong style="color:#fff;">candidates</strong> — you choose what to import.
        Discovery never auto-adds devices.
    </p>

    <div style="background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
                <div style="font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.7px;margin-bottom:4px;">Configured subnets</div>
                <div style="font-size:13px;font-family:monospace;color:#4da3ff;"><?= htmlspecialchars(nms('discovery_subnets','—  (not set)')) ?></div>
            </div>
            <div>
                <div style="font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.7px;margin-bottom:4px;">Schedule</div>
                <div style="font-size:13px;color:#fff;"><?= htmlspecialchars(nms('discovery_schedule','manual')) ?></div>
            </div>
        </div>
        <?php if (!nms('discovery_subnets')): ?>
        <div style="margin-top:8px;font-size:11px;color:#f39c12;"><i class="fas fa-exclamation-triangle"></i>
            Configure subnets in the <a href="#" onclick="showTab('settings');return false;" style="color:var(--accent);">Settings tab</a> first.
        </div>
        <?php endif ?>
    </div>

    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px;">
        <button class="btn btn-primary" onclick="runDiscovery()" id="disc-run-btn">
            <i class="fas fa-play"></i> Run Discovery Now
        </button>
        <div id="disc-status" style="font-size:12px;color:#888;"></div>
    </div>

    <div id="disc-output" style="display:none;background:rgba(0,0,0,.5);border:1px solid #333;border-radius:8px;
         padding:12px;font-size:11px;color:#2ecc71;font-family:monospace;max-height:220px;overflow-y:auto;
         white-space:pre-wrap;line-height:1.6;"></div>
</div>

<div class="glass-card" style="border-color:rgba(243,156,18,.2);">
    <h2 style="color:var(--warn);"><i class="fas fa-circle-info"></i> How it works</h2>
    <ol style="margin:0;padding-left:20px;font-size:12px;color:#888;line-height:2;">
        <li>Pings every host in each configured subnet</li>
        <li>SNMP-probes live hosts with your community strings</li>
        <li>Unknown hosts appear as <strong style="color:var(--warn);">pending</strong> candidates</li>
        <li>You click <strong style="color:var(--up);">Import</strong> to add to monitored nodes</li>
        <li>Poller auto-discovers interfaces on next cycle</li>
    </ol>
    <div style="margin-top:12px;font-size:11px;color:#555;border-top:1px solid var(--border);padding-top:10px;">
        <i class="fas fa-shield-halved" style="color:var(--up);"></i>
        Hosts already in <strong>Nodes</strong> are automatically skipped.
    </div>
</div>
</div>

<!-- Right: Candidates -->
<div>
<div class="glass-card">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px;">
        <h2 style="margin:0;"><i class="fas fa-list-check"></i> Candidates</h2>
        <div style="display:flex;gap:8px;">
            <button class="btn btn-sm" style="border-color:#555;color:#888;" onclick="loadCandidates()">
                <i class="fas fa-sync-alt"></i> Refresh
            </button>
            <button class="btn btn-danger btn-sm" onclick="clearRejected()">
                <i class="fas fa-trash"></i> Clear Rejected
            </button>
        </div>
    </div>
    <div id="candidates-content">
        <div style="text-align:center;color:#555;padding:30px;">
            <span class="spinner"></span>&nbsp; Loading…
        </div>
    </div>
</div>
</div>

</div><!-- /two-col -->
</div><!-- /tab-discovery -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB: Integrations & AI  (Graylog logs + n8n automation/AI foundation)   -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-integrations" class="tab-panel <?= $tab==='integrations'?'active':'' ?>">
<div class="int-masonry">
<div class="im-col">

<?php
  $_alloyPort = ($r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='alloy_port'")) && ($x=$r->fetch_assoc()) ? $x['setting_val'] : '12345';
  $_alloyPath = ($r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='alloy_path'")) && ($x=$r->fetch_assoc()) ? $x['setting_val'] : '/metrics';
?>
<!-- ── Grafana Alloy (Linux Monitor metrics source) ──────────────── -->
<div class="glass-card" style="border-color:rgba(247,103,7,.35);">
    <h2><i class="fas fa-chart-line" style="color:#f76707;"></i> Grafana Alloy <span style="font-size:11px;color:#f76707;font-weight:400;">(Linux Monitor metrics)</span></h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">Lets the <a href="linux.php" style="color:var(--accent);">Linux Monitor</a> read live system metrics from each box's <b>Grafana Alloy</b> instead of SSH. Per host you pick the source (<b>SSH</b> or <b>Alloy</b>) when you add/edit it; these are the <b>defaults</b> used to build the per-host URL <code>http://&lt;host-ip&gt;:&lt;port&gt;&lt;path&gt;</code>.</p>
    <form method="post" action="net_mon_config.php?tab=integrations">
        <input type="hidden" name="action" value="save_alloy">
        <div class="form-row" style="display:flex;gap:10px;">
            <div style="flex:0 0 120px;"><label>Alloy port</label><input type="number" name="alloy_port" value="<?= htmlspecialchars($_alloyPort) ?>" min="1" max="65535"></div>
            <div style="flex:1;"><label>Metrics path</label><input type="text" name="alloy_path" value="<?= htmlspecialchars($_alloyPath) ?>" placeholder="/metrics"></div>
        </div>
        <button class="btn-primary" type="submit" style="margin-top:10px;"><i class="fas fa-save"></i> Save Alloy defaults</button>
    </form>
    <div style="margin-top:14px;padding:11px 13px;background:rgba(247,103,7,.06);border:1px solid rgba(247,103,7,.25);border-radius:10px;">
        <b style="font-size:12px;color:#f7a35c;"><i class="fas fa-circle-info"></i> How to enable it on a Linux box (step by step)</b>
        <ol style="margin:8px 0 0;padding-left:18px;font-size:12px;color:#aab;line-height:1.7;">
            <li><b>Expose node/system metrics on the box.</b> NEURU reads the standard Prometheus <code>node_*</code> metrics. The simplest, reliable way is the official <b>node_exporter</b> container (Alloy's own <code>/metrics</code> only serves Alloy's internal telemetry, not the box):
              <pre style="background:#0a0d12;border:1px solid var(--border);border-radius:8px;padding:9px;font-size:11px;color:#bfe8c9;white-space:pre-wrap;margin:6px 0;">docker run -d --name node-exporter --restart unless-stopped \
  --net host --pid host -v "/:/host:ro,rslave" \
  quay.io/prometheus/node-exporter:latest --path.rootfs=/host</pre>
              That serves metrics at <code>http://&lt;ip&gt;:9100/metrics</code>. <span style="font-size:11px;color:#7d8aa0;">Tip: set the <b>port above to 9100</b> so blank per-host URLs auto-build correctly. (Alloy can also collect these and remote_write to a Prometheus for a central setup, but for per-device reading node_exporter is the direct path.)</span></li>
            <li>In <a href="linux.php" style="color:var(--accent);">Linux Monitor → Add/Edit host</a>, set <b>Live metrics source = Grafana Alloy / node_exporter</b>. The URL pre-fills to <code>http://&lt;ip&gt;:<?= htmlspecialchars($_alloyPort) ?><?= htmlspecialchars($_alloyPath) ?></code> from your node's IP + the port/path above — edit it if needed.</li>
            <li>Hit <b>Troubleshoot</b> / <b>Command Center</b> — CPU, memory, disks, network &amp; temps now come from Alloy (no SSH needed). <span style="color:#7d8aa0;">Per-process "top consumers", kill, services and journal still use SSH — set an SSH credential too if you want those.</span></li>
        </ol>
    </div>
</div>

<!-- ── Logs (NEURU syslog server — default; Graylog optional) ──────── -->
<div class="glass-card" style="border-color:rgba(13,183,237,.35);">
    <h2><i class="fas fa-server" style="color:#0db7ed;"></i> NEURU Syslog Server <span style="font-size:11px;color:#0db7ed;font-weight:400;">(default log source)</span></h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">Built-in syslog receiver — devices send to this host and logs land straight in NEURU's DB. View under <a href="log_mon.php" style="color:var(--accent);">Logs</a>. Graylog below is optional.</p>
    <div id="sy-status" class="conn-status conn-unk" style="margin-bottom:14px;"><i class="fas fa-circle-question"></i> <span id="sy-status-text">Checking receiver…</span></div>
    <div class="form-row">
        <label>Active log source</label>
        <select class="form-input" id="sy-source">
            <option value="syslog" <?= $_sy['log_source']!=='graylog'?'selected':'' ?>>NEURU Syslog Server (default)</option>
            <option value="graylog" <?= $_sy['log_source']==='graylog'?'selected':'' ?>>Graylog (optional)</option>
        </select>
    </div>
    <div class="form-row" style="display:flex;gap:10px;">
        <div style="flex:1;"><label>Listen port</label><input class="form-input" type="number" id="sy-port" value="<?= htmlspecialchars($_sy['syslog_port']) ?>" placeholder="514"></div>
        <div style="flex:1;"><label>Retention (days)</label><input class="form-input" type="number" id="sy-ret" value="<?= htmlspecialchars($_sy['syslog_retention_days']) ?>" placeholder="30"></div>
        <div style="flex:1;"><label>TCP</label><div class="toggle-wrap"><label class="toggle-switch"><input type="checkbox" id="sy-tcp" <?= $_sy['syslog_tcp_enabled']?'checked':'' ?>><span class="toggle-slider"></span></label></div></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;">
        <button type="button" class="btn btn-primary btn-sm" onclick="syslogStatus()"><i class="fas fa-rotate"></i> Check</button>
        <button type="button" class="btn btn-success btn-sm" onclick="saveSyslog()"><i class="fas fa-floppy-disk"></i> Save</button>
    </div>
    <p style="font-size:11px;color:#666;margin:14px 0 0;border-top:1px solid rgba(255,255,255,.06);padding-top:10px;">
        <i class="fas fa-circle-info"></i> Run the daemon: <code style="color:#9aa;">/opt/netmon-venv/bin/python3 /var/www/html/netmon/scripts/nm_syslog.py</code> (port 514 needs root / a 514→port map). Point devices' syslog at this host. Restart the daemon after changing the port.
    </p>
</div>

<div class="glass-card" style="border-color:rgba(77,163,255,.3);margin-top:16px;">
    <h2><i class="fas fa-file-lines" style="color:var(--accent);"></i> Graylog — Log Source <span style="font-size:11px;color:#666;font-weight:400;">(optional)</span></h2>
    <p style="font-size:11px;color:#888;margin:0 0 14px;">
        Centralised syslog/event logs. Each device's logs are pulled live by matching the Graylog
        <code>source</code> field to the node's IP / name. View them under
        <a href="log_mon.php" style="color:var(--accent);">Logs</a>.
    </p>
    <div id="gl-status" class="conn-status conn-unk" style="margin-bottom:14px;">
        <i class="fas fa-circle-question"></i> <span id="gl-status-text">Click "Test" to check status.</span>
    </div>
    <form method="post">
        <input type="hidden" name="action" value="save_graylog">
        <div class="form-row">
            <label>Graylog URL</label>
            <input class="form-input" type="text" id="gl-url" name="graylog_url"
                   value="<?= htmlspecialchars($_graylog_cfg['url']) ?>" placeholder="http://192.168.0.240:9000" autocomplete="off">
        </div>
        <div class="form-row">
            <label>API Token <span style="color:#555;font-weight:400;">(Graylog access token)</span></label>
            <input class="form-input" type="password" id="gl-token" name="graylog_token"
                   value="<?= htmlspecialchars($_graylog_cfg['token']) ?>" placeholder="Graylog access token" autocomplete="off">
        </div>
        <div class="form-row">
            <label>Enable</label>
            <div class="toggle-wrap">
                <label class="toggle-switch">
                    <input type="checkbox" name="graylog_enabled" <?= $_graylog_cfg['enabled']?'checked':'' ?>>
                    <span class="toggle-slider"></span>
                </label>
                <span style="font-size:12px;color:<?= $_graylog_cfg['enabled']?'var(--up)':'var(--down)' ?>;">
                    <?= $_graylog_cfg['enabled']?'Enabled':'Disabled' ?></span>
            </div>
        </div>
        <div style="display:flex;gap:8px;margin-top:12px;">
            <button type="button" class="btn btn-primary btn-sm" onclick="testGraylog()"><i class="fas fa-satellite-dish"></i> Test</button>
            <button type="submit" class="btn btn-success btn-sm"><i class="fas fa-floppy-disk"></i> Save</button>
        </div>
    </form>
    <p style="font-size:11px;color:#666;margin:14px 0 0;border-top:1px solid rgba(255,255,255,.06);padding-top:10px;">
        <i class="fas fa-circle-info"></i> Each device's Graylog <code>source</code> is inferred from its IP/name
        automatically; override it per-device right on the <a href="log_mon.php" style="color:var(--accent);">Logs</a> page.
    </p>
</div>

<!-- ── Smokeping — latency monitoring (optional embedded tool) ───────────── -->
<div class="glass-card" style="border-color:rgba(13,183,237,.3);margin-top:16px;">
    <h2><i class="fas fa-wave-square" style="color:#0db7ed;"></i> Smokeping — Latency Monitor</h2>
    <p style="font-size:11px;color:#888;margin:0 0 14px;">
        Embed your Smokeping latency/packet-loss grapher inside NEURU, and (optionally) add or remove
        monitored targets remotely through an n8n flow. View it under
        <a href="smokeping.php" style="color:var(--accent);">Smokeping</a>.
    </p>
    <div id="sp-status" class="conn-status conn-unk" style="margin-bottom:14px;">
        <i class="fas fa-circle-question"></i> <span id="sp-status-text">Click "Test" to check reachability.</span>
    </div>
    <form id="sp-form" onsubmit="return false;">
        <div class="form-row">
            <label>Smokeping URL <span style="color:#555;font-weight:400;">(web UI base)</span></label>
            <input class="form-input" type="text" id="sp-url" name="smokeping_url"
                   value="<?= htmlspecialchars($_sp['url']) ?>" placeholder="http://192.168.0.25:1010/smokeping/" autocomplete="off">
        </div>
        <div class="form-row">
            <label>Enable</label>
            <div class="toggle-wrap">
                <label class="toggle-switch">
                    <input type="checkbox" id="sp-enabled" name="smokeping_enabled" <?= $_sp['enabled']?'checked':'' ?>>
                    <span class="toggle-slider"></span>
                </label>
                <span id="sp-en-lbl" style="font-size:12px;color:<?= $_sp['enabled']?'var(--up)':'var(--down)' ?>;">
                    <?= $_sp['enabled']?'Enabled':'Disabled' ?></span>
            </div>
        </div>

        <div style="border-top:1px solid rgba(255,255,255,.06);margin:14px 0 12px;padding-top:12px;">
            <div style="font-size:12px;font-weight:600;color:#0db7ed;margin-bottom:4px;"><i class="fas fa-screwdriver-wrench"></i> Remote target management <span style="color:#666;font-weight:400;">(optional — needs an n8n flow)</span></div>
            <p style="font-size:11px;color:#777;margin:0 0 12px;">NEURU composes a safe <code>docker exec</code> command to edit the Targets file and posts it to your n8n webhook, which SSHes to the host and runs it (no AI). Leave the webhook blank to use the embed only.</p>
        </div>
        <div class="form-row">
            <label>Docker host IP <span style="color:#555;font-weight:400;">(where the Smokeping container runs)</span></label>
            <input class="form-input" type="text" id="sp-host" name="smokeping_host_ip"
                   value="<?= htmlspecialchars($_sp['host_ip']) ?>" placeholder="192.168.0.25" autocomplete="off">
        </div>
        <div class="form-row" style="display:flex;gap:10px;">
            <div style="flex:1;"><label>Container name</label>
                <input class="form-input" type="text" id="sp-container" name="smokeping_container"
                       value="<?= htmlspecialchars($_sp['container']) ?>" placeholder="smokeping" autocomplete="off"></div>
            <div style="flex:1.4;"><label>Targets file (in container)</label>
                <input class="form-input" type="text" id="sp-path" name="smokeping_targets_path"
                       value="<?= htmlspecialchars($_sp['targets_path']) ?>" placeholder="/config/Targets" autocomplete="off"></div>
        </div>
        <div class="form-row">
            <label>RRD data dir (in container) <span style="color:#555;font-weight:400;">(for latency values)</span></label>
            <input class="form-input" type="text" id="sp-data" name="smokeping_data_path"
                   value="<?= htmlspecialchars($_sp['data_path']) ?>" placeholder="/data" autocomplete="off">
        </div>
        <div class="form-row">
            <label>Host access</label>
            <p style="font-size:11.5px;color:#7CFFB2;margin:2px 0 0;line-height:1.5;"><i class="fas fa-bolt"></i> Smokeping is now read &amp; managed <b>natively over SSH</b> — no n8n webhook needed. Just assign an SSH credential to the Docker host <b><?= htmlspecialchars($_sp['host_ip'] ?: 'above') ?></b> in <a href="?tab=ssh" style="color:var(--accent);">Config → SSH Credentials</a>.</p>
        </div>
        <div class="form-row">
            <label>Reload command <span style="color:#555;font-weight:400;">(after edits; blank = default)</span></label>
            <input class="form-input" type="text" id="sp-reload" name="smokeping_reload_cmd"
                   value="<?= htmlspecialchars($_sp['reload_cmd']) ?>" placeholder="docker exec smokeping smokeping --reload || docker restart smokeping" autocomplete="off">
        </div>

        <div style="border-top:1px solid rgba(255,255,255,.06);margin:14px 0 12px;padding-top:12px;">
            <div style="font-size:12px;font-weight:600;color:#0db7ed;margin-bottom:4px;"><i class="fas fa-bell"></i> Latency alerts <span style="color:#666;font-weight:400;">(margins you can adjust)</span></div>
            <p style="font-size:11px;color:#777;margin:0 0 12px;">Global defaults — override per node on the <a href="smokeping.php" style="color:var(--accent);">Smokeping</a> page. Alerts fire when a node breaches for N consecutive samples.</p>
        </div>
        <div class="form-row">
            <label>Enable latency alerts</label>
            <div class="toggle-wrap">
                <label class="toggle-switch"><input type="checkbox" id="sp-al-en" name="smokeping_alerts_enabled" <?= $_sp['alerts_enabled']?'checked':'' ?>><span class="toggle-slider"></span></label>
            </div>
        </div>
        <div class="form-row" style="display:flex;gap:10px;">
            <div style="flex:1;"><label>RTT warn (ms)</label><input class="form-input" type="number" step="0.1" id="sp-rw" value="<?= htmlspecialchars($_sp_thr['rtt_warn']) ?>" placeholder="80"></div>
            <div style="flex:1;"><label>RTT crit (ms)</label><input class="form-input" type="number" step="0.1" id="sp-rc" value="<?= htmlspecialchars($_sp_thr['rtt_crit']) ?>" placeholder="200"></div>
            <div style="flex:1;"><label>Loss warn</label><input class="form-input" type="number" step="0.1" id="sp-lw" value="<?= htmlspecialchars($_sp_thr['loss_warn']) ?>" placeholder="1"></div>
            <div style="flex:1;"><label>Loss crit</label><input class="form-input" type="number" step="0.1" id="sp-lc" value="<?= htmlspecialchars($_sp_thr['loss_crit']) ?>" placeholder="10"></div>
        </div>
        <div class="form-row" style="display:flex;gap:10px;">
            <div style="flex:1;"><label>Sustain (consecutive samples)</label><input class="form-input" type="number" min="1" max="10" id="sp-sustain" value="<?= (int)$_sp['alert_sustain'] ?>" placeholder="2"></div>
            <div style="flex:2.2;"><label>Notify webhook <span style="color:#555;font-weight:400;">(optional — n8n on open/clear)</span></label><input class="form-input" type="text" id="sp-alurl" value="<?= htmlspecialchars($_sp['alert_url']) ?>" placeholder="http://192.168.0.25:5678/webhook/latency-alert" autocomplete="off"></div>
        </div>
        <div style="display:flex;gap:8px;margin-top:12px;">
            <button type="button" class="btn btn-primary btn-sm" onclick="testSmokeping()"><i class="fas fa-satellite-dish"></i> Test</button>
            <button type="button" class="btn btn-success btn-sm" onclick="saveSmokeping()"><i class="fas fa-floppy-disk"></i> Save</button>
        </div>
    </form>
    <p style="font-size:11px;color:#666;margin:14px 0 0;border-top:1px solid rgba(255,255,255,.06);padding-top:10px;">
        <i class="fas fa-circle-info"></i> SSH to the host is resolved from your <b>SSH Credentials</b> (assign one to the host IP),
        reusing the same path as container self-heal. The n8n flow is a single Webhook → SSH(run <code>{{$json.command}}</code>) → Respond.
    </p>
</div>

<!-- ── Pi-hole (multi-instance) ─────────────────────────────────────────────── -->
<div class="glass-card" style="border-color:rgba(246,13,26,.35);">
    <h2 style="color:#f60d1a;"><i class="fas fa-shield-halved"></i> Pi-hole <span style="font-size:11px;color:#666;font-weight:400;">— add one or more</span></h2>
    <p style="font-size:11px;color:#888;margin:0 0 14px;">Pull DNS stats, top lists and the live query log from each Pi-hole v6 (password auth, no app token).
        NEURU proxies server-side — passwords stay encrypted and never reach the browser. Add as many Pi-holes as you run; switch between them on the Pi-hole page.</p>

    <table class="dev-table" id="ph-table" style="margin-bottom:12px;"><thead><tr>
        <th>Name</th><th>Address</th><th>TLS</th><th>Status</th><th style="text-align:right;">Actions</th>
    </tr></thead><tbody id="ph-tbody">
        <?php if (empty($_ph_servers)): ?>
        <tr><td colspan="5" style="color:#888;text-align:center;padding:14px;">No Pi-holes yet — add one below.</td></tr>
        <?php else: foreach ($_ph_servers as $s): ?>
        <tr data-id="<?= (int)$s['id'] ?>">
            <td><b><?= htmlspecialchars($s['name']) ?></b></td>
            <td class="mono" style="font-size:11px;"><?= htmlspecialchars($s['url']) ?></td>
            <td><?= $s['verify'] ? 'verify' : '<span style="color:#888;">skip</span>' ?></td>
            <td><span class="conn-status <?= $s['enabled']?($s['has_pw']?'conn-ok':'conn-unk'):'conn-off' ?>" style="padding:2px 8px;font-size:10px;">
                <?= $s['enabled'] ? ($s['has_pw']?'enabled':'no password') : 'disabled' ?></span></td>
            <td style="text-align:right;white-space:nowrap;">
                <button class="btn btn-sm" title="Test" onclick="testPihole(<?= (int)$s['id'] ?>,this)"><i class="fas fa-satellite-dish"></i></button>
                <button class="btn btn-sm" title="Edit" onclick="editPihole(<?= (int)$s['id'] ?>)"><i class="fas fa-pen"></i></button>
                <button class="btn btn-sm btn-danger" title="Delete" onclick="deletePihole(<?= (int)$s['id'] ?>,'<?= htmlspecialchars(addslashes($s['name'])) ?>')"><i class="fas fa-trash"></i></button>
            </td>
        </tr>
        <?php endforeach; endif; ?>
    </tbody></table>

    <div id="ph-status" class="conn-status conn-unk" style="margin-bottom:12px;display:none;">
        <i class="fas fa-circle-question"></i> <span id="ph-status-text"></span>
    </div>

    <form id="ph-form" onsubmit="return false;" style="border-top:1px solid rgba(255,255,255,.06);padding-top:12px;">
        <div style="font-size:11px;color:#888;margin-bottom:8px;"><b id="ph-form-title">Add a Pi-hole</b></div>
        <input type="hidden" id="ph-id" value="0">
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <div class="form-row" style="flex:1;min-width:140px;"><label>Name</label>
                <input class="form-input" type="text" id="ph-name" placeholder="Pi-hole 1" autocomplete="off"></div>
            <div class="form-row" style="flex:2;min-width:200px;"><label>Address <span style="color:#555;font-weight:400;">(scheme + host[:port], no /api)</span></label>
                <input class="form-input" type="text" id="ph-url" placeholder="https://192.168.80.10  or  https://192.168.0.30:4443" autocomplete="off"></div>
        </div>
        <div class="form-row">
            <label>Web/API password <span style="color:#555;font-weight:400;" id="ph-pw-hint">(required)</span></label>
            <input class="form-input" type="password" id="ph-password" value="" placeholder="Pi-hole admin password" autocomplete="new-password">
        </div>
        <div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin-top:4px;">
            <label style="display:flex;align-items:center;gap:8px;"><span class="toggle-switch"><input type="checkbox" id="ph-enabled" checked><span class="toggle-slider"></span></span><span style="font-size:12px;">Enabled</span></label>
            <label style="display:flex;align-items:center;gap:8px;"><span class="toggle-switch"><input type="checkbox" id="ph-verify"><span class="toggle-slider"></span></span><span style="font-size:12px;color:#aaa;">Verify TLS <span style="color:#666;">(off for self-signed)</span></span></label>
        </div>
        <div style="display:flex;gap:8px;margin-top:14px;">
            <button type="button" class="btn btn-success btn-sm" onclick="savePihole()"><i class="fas fa-floppy-disk"></i> <span id="ph-save-lbl">Add Pi-hole</span></button>
            <button type="button" class="btn btn-sm" id="ph-cancel" style="display:none;" onclick="resetPiholeForm()">Cancel</button>
            <a class="btn btn-sm" href="pihole.php" style="margin-left:auto;"><i class="fas fa-arrow-up-right-from-square"></i> Open Pi-hole</a>
        </div>
    </form>
</div>

</div><!-- /im-col --><div class="im-col">

<!-- ── NetFlow Traffic Analyzer ─────────────────────────────────────────────── -->
<div class="glass-card" style="border-color:rgba(77,163,255,.35);">
    <h2 style="color:#4da3ff;"><i class="fas fa-chart-area"></i> NetFlow Traffic Analyzer</h2>
    <p style="font-size:11px;color:#888;margin:0 0 14px;">Receive NetFlow v5/v9 &amp; IPFIX exports from your routers and analyze bandwidth by
        application, talker, conversation and protocol — plus alerts when an app spikes above normal. The Python collector aggregates per minute (top-N) so it stays light.</p>
    <div id="nf-status" class="conn-status <?= $_nf_status['alive']?'conn-ok':'conn-unk' ?>" style="margin-bottom:14px;">
        <i class="fas <?= $_nf_status['alive']?'fa-circle-check':'fa-circle-question' ?>"></i>
        <span id="nf-status-text"><?php if($_nf_status['alive']): ?>Collector live — <?= number_format($_nf_status['flows']) ?> flows, <?= number_format($_nf_status['packets']) ?> packets<?php elseif($_nf_status['last_flush_ts']): ?>Collector stale (<?= (int)$_nf_status['age_sec'] ?>s ago)<?php else: ?>No flow data yet — enable, then point routers at this server.<?php endif; ?></span>
    </div>
    <form id="nf-form" onsubmit="return false;">
        <div class="form-row" style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
            <label class="toggle-switch"><input type="checkbox" id="nf-enabled" name="netflow_enabled" value="1" <?= $_nf['enabled']?'checked':'' ?>><span class="toggle-slider"></span></label>
            <span style="font-size:13px;">Enable NetFlow collection</span>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <div class="form-row" style="flex:1;min-width:120px;"><label>Listen port (UDP)</label>
                <input class="form-input" type="number" id="nf-port" name="netflow_port" value="<?= (int)$_nf['port'] ?>" placeholder="2055"></div>
            <div class="form-row" style="flex:1;min-width:120px;"><label>Retention (days)</label>
                <input class="form-input" type="number" id="nf-ret" name="netflow_retention_days" value="<?= (int)$_nf['retention_days'] ?>"></div>
            <div class="form-row" style="flex:1;min-width:120px;"><label>Sampling rate</label>
                <input class="form-input" type="number" id="nf-samp" name="netflow_sampling" value="<?= (int)$_nf['sampling'] ?>" title="1 = unsampled. If your router samples 1:N, set N."></div>
            <div class="form-row" style="flex:1;min-width:120px;"><label>Top-N per minute</label>
                <input class="form-input" type="number" id="nf-topn" name="netflow_topn" value="<?= (int)$_nf['topn'] ?>" title="How many busiest conversations to keep per minute."></div>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <div class="form-row" style="flex:1;min-width:120px;"><label>Baseline anomaly ×</label>
                <input class="form-input" type="number" id="nf-base" name="netflow_baseline_mult" value="<?= (int)$_nf['baseline_mult'] ?>" title="Alert when an app exceeds this multiple of its 24h average."></div>
            <div class="form-row" style="flex:3;min-width:200px;"><label>Alert webhook <span style="color:#555;font-weight:400;">(optional — n8n on open)</span></label>
                <input class="form-input" type="text" id="nf-alurl" name="netflow_alert_url" value="<?= htmlspecialchars($_nf['alert_url']) ?>" placeholder="http://192.168.0.25:5678/webhook/netflow-alert" autocomplete="off"></div>
        </div>
        <p style="font-size:11px;color:#666;margin:6px 0 0;border-top:1px solid rgba(255,255,255,.06);padding-top:10px;">
            <i class="fas fa-circle-info"></i> Point your router's flow export here. <b>MikroTik:</b> IP → Traffic Flow → enable, add target
            <b>this-server:<?= (int)$_nf['port'] ?></b>, version <b>9</b> (or 5). <b>Cisco:</b> <code>ip flow-export destination &lt;ip&gt; <?= (int)$_nf['port'] ?></code> + <code>version 9</code>.
            The UDP port must be published on the container (e.g. <code><?= (int)$_nf['port'] ?>:<?= (int)$_nf['port'] ?>/udp</code>).
        </p>
        <div style="display:flex;gap:8px;margin-top:14px;">
            <button type="button" class="btn btn-primary btn-sm" onclick="checkNetflow()"><i class="fas fa-satellite-dish"></i> Check status</button>
            <button type="button" class="btn btn-success btn-sm" onclick="saveNetflow()"><i class="fas fa-floppy-disk"></i> Save</button>
            <a class="btn btn-sm" href="netflow.php" style="margin-left:auto;"><i class="fas fa-arrow-up-right-from-square"></i> Open NetFlow Analyzer</a>
        </div>
    </form>
</div>

<!-- ── SMTP (email delivery — any provider) ─────────────────────────────────── -->
<div class="glass-card" style="border-color:rgba(46,204,113,.3);">
    <h2 style="color:#2ecc71;"><i class="fas fa-envelope"></i> SMTP — Email Delivery</h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">Used to send incident emails &amp; reports. Works with <b>any provider</b> (Gmail, Office365, SendGrid, your own server).
        <b>Gmail:</b> host <code>smtp.gmail.com</code>, port <code>587</code>, security <code>STARTTLS</code>, user = your address, password = a Google <b>App Password</b> (not your login).</p>
    <div id="smtp-status" class="conn-status conn-unk" style="margin-bottom:12px;display:none;"><i class="fas fa-circle-question"></i> <span id="smtp-status-text"></span></div>
    <form id="smtp-form" onsubmit="return false;">
        <div class="form-row" style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
            <label class="toggle-switch"><input type="checkbox" id="smtp-enabled" <?= $_smtp['enabled']?'checked':'' ?>><span class="toggle-slider"></span></label>
            <span style="font-size:13px;">Enable email delivery</span>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <div class="form-row" style="flex:2;min-width:180px;"><label>SMTP host</label>
                <input class="form-input" type="text" id="smtp-host" value="<?= htmlspecialchars($_smtp['host']) ?>" placeholder="smtp.gmail.com" autocomplete="off"></div>
            <div class="form-row" style="flex:1;min-width:90px;"><label>Port</label>
                <input class="form-input" type="number" id="smtp-port" value="<?= (int)$_smtp['port'] ?>" placeholder="587"></div>
            <div class="form-row" style="flex:1;min-width:120px;"><label>Security</label>
                <select class="form-select" id="smtp-secure">
                    <option value="tls" <?= $_smtp['secure']==='tls'?'selected':'' ?>>STARTTLS (587)</option>
                    <option value="ssl" <?= $_smtp['secure']==='ssl'?'selected':'' ?>>SSL/TLS (465)</option>
                    <option value="none" <?= $_smtp['secure']==='none'?'selected':'' ?>>None (25)</option>
                </select></div>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <div class="form-row" style="flex:1;min-width:160px;"><label>Username</label>
                <input class="form-input" type="text" id="smtp-user" value="<?= htmlspecialchars($_smtp['user']) ?>" placeholder="you@gmail.com" autocomplete="off"></div>
            <div class="form-row" style="flex:1;min-width:160px;"><label>Password <span style="color:#555;font-weight:400;"><?= $_smtp['has_pass']?'(saved — blank to keep)':'(app password)' ?></span></label>
                <input class="form-input" type="password" id="smtp-pass" value="" placeholder="<?= $_smtp['has_pass']?'•••••••• (unchanged)':'app password' ?>" autocomplete="new-password"></div>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <div class="form-row" style="flex:1;min-width:160px;"><label>From address</label>
                <input class="form-input" type="text" id="smtp-from" value="<?= htmlspecialchars($_smtp['from']) ?>" placeholder="(defaults to username)" autocomplete="off"></div>
            <div class="form-row" style="flex:1;min-width:120px;"><label>From name</label>
                <input class="form-input" type="text" id="smtp-from-name" value="<?= htmlspecialchars($_smtp['from_name']) ?>" placeholder="NEURU"></div>
        </div>
        <div style="display:flex;gap:8px;margin-top:14px;align-items:center;">
            <input class="form-input" type="text" id="smtp-test-to" placeholder="test recipient (optional)" style="max-width:220px;">
            <button type="button" class="btn btn-primary btn-sm" onclick="testSmtp()"><i class="fas fa-paper-plane"></i> Send test</button>
            <button type="button" class="btn btn-success btn-sm" onclick="saveSmtp()"><i class="fas fa-floppy-disk"></i> Save</button>
        </div>
    </form>
</div>

<!-- ── n8n automation + AI foundation ────────────────────────────── -->
<div class="glass-card" style="border-color:rgba(155,89,182,.35);">
    <h2 style="color:#b07cd6;"><i class="fas fa-robot"></i> n8n Automation &amp; AI</h2>
    <p style="font-size:11px;color:#888;margin:0 0 14px;">
        The portal talks to n8n flows for AI (anomaly detection, log RCA, the NetOps copilot, self-healing).
        Configure the connection both ways below.
    </p>

    <!-- Outbound: n8n API -->
    <h3 style="font-size:12px;color:#b07cd6;margin:6px 0 8px;text-transform:uppercase;letter-spacing:1px;">Portal → n8n</h3>
    <div class="form-row">
        <label>n8n Base URL</label>
        <input class="form-input" type="text" id="n8n-base" value="<?= htmlspecialchars($_n8n_cfg['base_url']) ?>" placeholder="http://192.168.0.240:5678" autocomplete="off">
    </div>
    <div class="form-row">
        <label>n8n API Key <span style="color:#555;font-weight:400;">(for triggering flows via n8n REST API)</span></label>
        <input class="form-input" type="password" id="n8n-key" value="<?= htmlspecialchars($_n8n_cfg['api_key']) ?>" placeholder="n8n API key" autocomplete="off">
    </div>
    <div class="form-row">
        <label>Portal Base URL <span style="color:#555;font-weight:400;">(how n8n reaches THIS portal for callbacks)</span></label>
        <input class="form-input" type="text" id="n8n-portal" value="<?= htmlspecialchars($_n8n_cfg['portal_base'] ?? '') ?>" placeholder="http://192.168.0.25:8090" autocomplete="off">
        <p style="font-size:11px;color:#888;margin:6px 0 0;">Flows like <code>db-advisor</code> / <code>bio-dns-audit</code> / <code>bio-http-synthetic</code> post results back here. From the n8n container <code>localhost</code> is n8n itself, so set the portal's LAN URL (else callbacks fail with ECONNREFUSED). Blank = <code>http://localhost</code>.</p>
    </div>
    <button type="button" class="btn btn-success btn-sm" onclick="saveN8n()"><i class="fas fa-floppy-disk"></i> Save n8n API</button>

    <!-- Inbound token -->
    <h3 style="font-size:12px;color:#b07cd6;margin:18px 0 8px;text-transform:uppercase;letter-spacing:1px;">n8n → Portal (inbound auth)</h3>
    <p style="font-size:11px;color:#888;margin:0 0 10px;">
        n8n flows call back into the portal (<code>nm_ai_ingest.php</code>) carrying this token in the
        <code>X-NetMon-Token</code> header. Generate it once and paste it into your n8n credentials.
    </p>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <input class="form-input" type="text" id="n8n-token" readonly style="flex:1;min-width:220px;font-family:monospace;font-size:11px;"
               value="<?= htmlspecialchars($_n8n_cfg['inbound_token']) ?>" placeholder="— not generated yet —">
        <button type="button" class="btn btn-sm" onclick="copyToken()"><i class="fas fa-copy"></i></button>
        <button type="button" class="btn btn-primary btn-sm" onclick="genToken()"><i class="fas fa-key"></i> <?= $_n8n_cfg['inbound_token']?'Rotate':'Generate' ?></button>
    </div>
    <span id="n8n-msg" style="font-size:11px;color:#2ecc71;"></span>

    <!-- AI Gateway (metered NEURU AI Flows service) -->
    <h3 style="font-size:12px;color:#36e3d0;margin:20px 0 8px;text-transform:uppercase;letter-spacing:1px;"><i class="fas fa-bolt"></i> AI Gateway <span style="color:#555;font-weight:400;text-transform:none;letter-spacing:0;">(NEURU AI Flows — metered)</span></h3>
    <p style="font-size:11px;color:#888;margin:0 0 10px;">
        Buying hosted AI flows from the <b>NEURU Portal</b>? You don't paste anything here — enter your
        <b>license key</b> once (License page), then hit <b>Sync my flows</b> and NEURU fills the connection
        key, gateway key and callback URL <b>automatically</b> from your subscription. NEURU sends them with
        every flow call so your usage is metered against your prepaid credit. (You can still type them by
        hand if you run your own n8n/LLM.)
    </p>
    <div class="form-row">
        <label>Connection key <span style="color:#555;font-weight:400;">(conn_key from the Portal)</span></label>
        <input class="form-input" type="text" id="ai-conn" value="<?= htmlspecialchars($_ai_gw['conn_key']) ?>" placeholder="conn_..." autocomplete="off" style="font-family:monospace;font-size:11px;">
    </div>
    <div class="form-row">
        <label>Gateway key / vkey <span style="color:#555;font-weight:400;">(your metered LiteLLM key)</span></label>
        <input class="form-input" type="text" id="ai-vkey" value="<?= htmlspecialchars($_ai_gw['vkey']) ?>" placeholder="sk-..." autocomplete="off" style="font-family:monospace;font-size:11px;">
    </div>
    <div class="form-row">
        <label>Public Base URL <span style="color:#555;font-weight:400;">(optional — how the flow reaches THIS NEURU for callbacks)</span></label>
        <input class="form-input" type="text" id="ai-pubbase" value="<?= htmlspecialchars($_ai_gw['public_base']) ?>" placeholder="https://my-neuru.example.com" autocomplete="off">
        <p style="font-size:11px;color:#888;margin:6px 0 0;">Only needed if this NEURU is behind a proxy/Cloudflare and cron-triggered flows must call back. Blank = auto-detected from the request.</p>
    </div>
    <button type="button" class="btn btn-success btn-sm" onclick="saveAiGateway()"><i class="fas fa-floppy-disk"></i> Save AI Gateway</button>
    <a href="flows_sync.php" onclick="window.open(this.href,'neuruFlows','width=640,height=680,menubar=no,toolbar=no,location=no,resizable=yes'); return false;" class="btn btn-sm" style="margin-left:6px;text-decoration:none;background:rgba(176,124,214,.16);border-color:#b07cd6;color:#d9bff0;"><i class="fas fa-arrows-rotate"></i> Sync my flows</a>
    <span id="ai-gw-msg" style="font-size:11px;color:#2ecc71;margin-left:8px;"></span>
    <p style="font-size:11px;color:#888;margin:8px 0 0;">
        <b>Sync my flows</b> pulls the flows you're subscribed to on the Portal and fills their n8n webhook URLs
        below automatically — no copy/paste. Runs on a schedule too. (No-op until the Portal enables it.)
    </p>

    <!-- WireGuard interconnect (NAT traversal for hosted flows) -->
    <h3 style="font-size:12px;color:#36e3d0;margin:20px 0 8px;text-transform:uppercase;letter-spacing:1px;"><i class="fas fa-plug-circle-bolt"></i> NEURU WG Connection <span style="color:#555;font-weight:400;text-transform:none;letter-spacing:0;">(let hosted flows reach this NEURU behind NAT)</span></h3>
    <p style="font-size:11px;color:#888;margin:0 0 10px;">
        Most installs sit behind NAT, so the hosted n8n can't deliver flow results back. Turn this ON and NEURU
        asks the Portal for a private <b>WireGuard</b> tunnel — no port-forwarding, no firewall rules. One switch.
        Off by default. Requires the WireGuard sidecar container (ships with new installs; existing installs add it once).
    </p>
    <a href="wg_connection.php" onclick="window.open(this.href,'neuruWG','width=820,height=700,menubar=no,toolbar=no,location=no,resizable=yes'); return false;" class="btn btn-sm" style="text-decoration:none;background:rgba(54,227,208,.14);border-color:#36e3d0;color:#8ff0e6;"><i class="fas fa-arrow-up-right-from-square"></i> Open WireGuard Connection</a>
    <span style="font-size:11px;color:#667;margin-left:8px;" id="wg-inline-state"></span>
</div>

<!-- Webhooks registry -->
<div class="glass-card" style="margin-top:14px;">
    <h2 style="display:flex;justify-content:space-between;align-items:center;">
        <span><i class="fas fa-diagram-next" style="color:#b07cd6;"></i> n8n Webhooks</span>
        <button class="btn btn-sm" onclick="webhookForm()"><i class="fas fa-plus"></i> Add</button>
    </h2>
    <p style="font-size:11px;color:#888;margin:0 0 10px;">
        Each AI/automation solution registers one webhook (a unique <em>slug</em> the portal calls by name).
        e.g. <code>log-rca</code>, <code>anomaly-baseline</code>, <code>netops-copilot</code>, <code>self-heal</code>.
    </p>
    <div id="wh-form" style="display:none;background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:12px;">
        <input type="hidden" id="wh-id" value="0">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
            <div><label style="font-size:10px;color:#aaa;">Name</label><input class="form-input" id="wh-name" placeholder="Log RCA"></div>
            <div><label style="font-size:10px;color:#aaa;">Slug</label><input class="form-input" id="wh-slug" placeholder="log-rca"></div>
        </div>
        <div style="margin-top:8px;"><label style="font-size:10px;color:#aaa;">Webhook URL</label><input class="form-input" id="wh-url" placeholder="http://192.168.0.240:5678/webhook/log-rca"></div>
        <div style="display:grid;grid-template-columns:auto 1fr auto;gap:8px;align-items:end;margin-top:8px;">
            <div><label style="font-size:10px;color:#aaa;">Method</label>
                <select class="form-select" id="wh-method"><option>POST</option><option>GET</option></select></div>
            <div><label style="font-size:10px;color:#aaa;">Description</label><input class="form-input" id="wh-desc" placeholder="Root-cause analysis for a device's logs"></div>
            <label style="font-size:11px;color:#aaa;display:flex;gap:6px;align-items:center;white-space:nowrap;"><input type="checkbox" id="wh-enabled" checked> Enabled</label>
        </div>
        <div style="display:flex;gap:8px;margin-top:10px;">
            <button class="btn btn-success btn-sm" onclick="saveWebhook()"><i class="fas fa-check"></i> Save</button>
            <button class="btn btn-sm" onclick="document.getElementById('wh-form').style.display='none'">Cancel</button>
        </div>
    </div>
    <div style="overflow-x:auto;">
        <table class="cfg-table" style="width:100%;font-size:12px;border-collapse:collapse;">
            <thead><tr style="color:#7c828c;font-size:10px;text-transform:uppercase;">
                <th style="text-align:left;padding:6px;">Name / Slug</th>
                <th style="text-align:left;padding:6px;">URL</th>
                <th style="padding:6px;">On</th><th></th>
            </tr></thead>
            <tbody id="wh-tbody"><tr><td colspan="4" style="color:#777;padding:12px;text-align:center;">Loading…</td></tr></tbody>
        </table>
    </div>
</div>

<!-- ── Adv. Solution Commander (Router/Linux AI-over-SSH) ─────────────── -->
<div class="glass-card" style="border-color:rgba(155,89,182,.35);">
    <h2 style="color:#b07cd6;"><i class="fas fa-network-wired"></i> Adv. Solution Commander <span style="font-size:11px;font-weight:400;color:#888;">— Router &amp; Linux AI-over-SSH</span></h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">AI troubleshooting webhooks for <a href="router_commander.php" style="color:var(--accent);">Adv. Solution Commander</a>. <b>rc_suggest</b> = the AI brain (routers + linux). <b>rc_execute</b> = bash SSH on <b>Linux</b> targets only — routers run over the portal's Python SSH and need no webhook. See <code>docs/N8N_ROUTER_COMMANDER.md</code>.</p>
    <div class="form-row">
        <label>rc_suggest_url <span style="color:#555;font-weight:400;">(AI analysis — router + linux)</span></label>
        <input class="form-input" type="text" id="rc-suggest" value="<?= htmlspecialchars($_rc['suggest']) ?>" placeholder="http://192.168.0.25:5678/webhook/rc-suggest" autocomplete="off">
    </div>
    <div class="form-row">
        <label>rc_execute_url <span style="color:#555;font-weight:400;">(Linux bash SSH only)</span></label>
        <input class="form-input" type="text" id="rc-exec" value="<?= htmlspecialchars($_rc['execute']) ?>" placeholder="http://192.168.0.25:5678/webhook/rc-exec" autocomplete="off">
    </div>
    <div style="display:flex;gap:8px;margin-top:8px;align-items:center;">
        <button type="button" class="btn btn-success btn-sm" onclick="saveRc()"><i class="fas fa-floppy-disk"></i> Save webhooks</button>
        <a class="btn btn-sm" href="router_commander.php" style="margin-left:auto;"><i class="fas fa-arrow-up-right-from-square"></i> Open</a>
        <span id="rc-msg" style="font-size:11px;color:#2ecc71;"></span>
    </div>
</div>

</div><!-- /im-col -->
</div><!-- /int-masonry -->
</div><!-- /tab-integrations -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB: Credentials (SSH credentials + per-device / docker-host assignment) -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-credentials" class="tab-panel <?= $tab==='credentials'?'active':'' ?>">
<div class="glass-card" style="border-color:rgba(46,204,113,.3);">
    <h2 style="display:flex;justify-content:space-between;align-items:center;">
        <span><i class="fas fa-key" style="color:#2ecc71;"></i> SSH Credentials <span style="font-size:11px;font-weight:400;color:#888;">— for self-heal “Approve &amp; Apply”</span></span>
        <button class="btn btn-sm" onclick="sshForm()"><i class="fas fa-plus"></i> Add credential</button>
    </h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">
        Secrets are <b>encrypted at rest</b> (AES-256-GCM) and never shown again. When you approve a remediation,
        the portal resolves the device's credential (its own, else the <b>default</b>) and passes it to the
        <code>self-heal-apply</code> flow's SSH node. You have the last word per device below.
    </p>
    <div id="ssh-form" style="display:none;background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:12px;">
        <input type="hidden" id="ssh-id" value="0">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;">
            <div><label style="font-size:10px;color:#aaa;">Name</label><input class="form-input" id="ssh-name" placeholder="MikroTik admin"></div>
            <div><label style="font-size:10px;color:#aaa;">Username</label><input class="form-input" id="ssh-user" placeholder="admin"></div>
            <div><label style="font-size:10px;color:#aaa;">Auth</label>
                <select class="form-select" id="ssh-auth" onchange="document.getElementById('ssh-sec-lbl').textContent=this.value==='key'?'Private key':'Password';">
                    <option value="password">Password</option><option value="key">Private key</option></select></div>
            <div><label style="font-size:10px;color:#aaa;">Port</label><input class="form-input" id="ssh-port" type="number" value="22" style="width:80px;"></div>
            <label style="font-size:11px;color:#aaa;display:flex;gap:6px;align-items:center;align-self:end;"><input type="checkbox" id="ssh-default"> Default</label>
        </div>
        <div style="margin-top:8px;"><label style="font-size:10px;color:#aaa;" id="ssh-sec-lbl">Password</label>
            <textarea class="form-input" id="ssh-secret" rows="2" placeholder="leave blank to keep existing on edit" style="font-family:monospace;"></textarea></div>
        <div style="display:flex;gap:8px;margin-top:10px;">
            <button class="btn btn-success btn-sm" onclick="sshSave()"><i class="fas fa-floppy-disk"></i> Save</button>
            <button class="btn btn-sm" onclick="document.getElementById('ssh-form').style.display='none'">Cancel</button>
        </div>
    </div>
    <div style="overflow-x:auto;">
        <table class="cfg-table" style="width:100%;font-size:12.5px;border-collapse:collapse;">
            <thead><tr style="color:#7c828c;font-size:10px;text-transform:uppercase;">
                <th style="text-align:left;padding:6px;">Name</th><th style="text-align:left;padding:6px;">User@Auth</th>
                <th style="padding:6px;">Port</th><th style="padding:6px;">Secret</th><th style="padding:6px;">Default</th><th></th>
            </tr></thead>
            <tbody id="ssh-tbody"><tr><td colspan="6" style="color:#777;padding:12px;text-align:center;">Loading…</td></tr></tbody>
        </table>
    </div>

    <h3 style="font-size:12px;color:#2ecc71;margin:18px 0 8px;text-transform:uppercase;letter-spacing:1px;">Per-device assignment</h3>
    <p style="font-size:11px;color:#888;margin:0 0 10px;">Pick which credential each device uses for remediation — or leave on <b>Default</b>.</p>
    <div style="overflow-x:auto;">
        <table class="cfg-table" style="width:100%;font-size:12.5px;border-collapse:collapse;">
            <thead><tr style="color:#7c828c;font-size:10px;text-transform:uppercase;">
                <th style="text-align:left;padding:6px;">Device</th><th style="text-align:left;padding:6px;">IP</th><th style="text-align:left;padding:6px;">Credential</th>
            </tr></thead>
            <tbody id="ssh-map-tbody"><tr><td colspan="3" style="color:#777;padding:12px;text-align:center;">Loading…</td></tr></tbody>
        </table>
    </div>

    <h3 style="font-size:12px;color:#0db7ed;margin:18px 0 8px;text-transform:uppercase;letter-spacing:1px;"><i class="fab fa-docker"></i> Container / Docker host assignment</h3>
    <p style="font-size:11px;color:#888;margin:0 0 10px;">SSH target for <b>container self-heal</b> (Auto-Fix). Pick the credential each Docker host uses — or leave on <b>Default</b>. Hosts come from Portainer.</p>
    <div style="overflow-x:auto;">
        <table class="cfg-table" style="width:100%;font-size:12.5px;border-collapse:collapse;">
            <thead><tr style="color:#7c828c;font-size:10px;text-transform:uppercase;">
                <th style="text-align:left;padding:6px;">Docker host</th><th style="text-align:left;padding:6px;">IP</th><th style="text-align:left;padding:6px;">Credential</th>
            </tr></thead>
            <tbody id="ssh-host-tbody"><tr><td colspan="3" style="color:#777;padding:12px;text-align:center;">Loading…</td></tr></tbody>
        </table>
    </div>
</div>

</div><!-- /tab-credentials -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB: Databases (Data Core targets — link a DB to a node + transport)    -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-databases" class="tab-panel <?= $tab==='databases'?'active':'' ?>">
<div class="glass-card" style="border-color:rgba(77,163,255,.3);">
    <h2 style="display:flex;justify-content:space-between;align-items:center;">
        <span><i class="fas fa-database" style="color:#4da3ff;"></i> Database Targets <span style="font-size:11px;font-weight:400;color:#888;">— monitored by <a href="dbmon.php" style="color:#4da3ff;">Data Core</a></span></span>
        <button class="btn btn-sm" onclick="dbForm()"><i class="fas fa-plus"></i> Add database</button>
    </h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">
        Link each database to the <b>monitored node</b> it runs on. <b>Direct</b> = the portal connects over TCP (needs the PDO driver in the image).
        <b>SSH</b> = NEURU runs the native client (<code>mysql</code>/<code>psql</code>) on the node using that node's SSH credential — no driver needed, works everywhere.
        Passwords are <b>encrypted at rest</b> (AES-256-GCM) and never shown again.
    </p>
    <div id="db-form" style="display:none;background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:12px;">
        <input type="hidden" id="db-id" value="0">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;">
            <div><label style="font-size:10px;color:#aaa;">Display name</label><input class="form-input" id="db-name" placeholder="Billing Postgres"></div>
            <div><label style="font-size:10px;color:#aaa;">Engine</label>
                <select class="form-select" id="db-engine" onchange="dbEngineChange()"></select></div>
            <div><label style="font-size:10px;color:#aaa;">Transport</label>
                <select class="form-select" id="db-transport" onchange="dbTransportChange()">
                    <option value="direct">Direct (PDO)</option><option value="ssh">SSH (native client)</option></select></div>
            <div><label style="font-size:10px;color:#aaa;">Linked node</label>
                <select class="form-select" id="db-node" onchange="dbNodeChange()"><option value="">— none —</option></select></div>
            <div><label style="font-size:10px;color:#aaa;">Replication role</label>
                <select class="form-select" id="db-role" onchange="dbRoleChange()">
                    <option value="standalone">Standalone</option><option value="master">Master / Source</option><option value="replica">Replica / Slave</option></select></div>
            <div id="db-replof-wrap" style="display:none;"><label style="font-size:10px;color:#aaa;">Replica of (master)</label>
                <select class="form-select" id="db-replof"><option value="">— select master —</option></select></div>
            <div><label style="font-size:10px;color:#aaa;">Host (from vantage)</label><input class="form-input" id="db-host" placeholder="127.0.0.1"></div>
            <div><label style="font-size:10px;color:#aaa;">Port</label><input class="form-input" id="db-port" type="number" style="width:90px;"></div>
            <div><label style="font-size:10px;color:#aaa;">Database name</label><input class="form-input" id="db-dbname" placeholder="optional"></div>
            <div><label style="font-size:10px;color:#aaa;">Username</label><input class="form-input" id="db-user" placeholder="monitor"></div>
            <div><label style="font-size:10px;color:#aaa;">Password</label><input class="form-input" id="db-pass" type="password" placeholder="blank = keep existing"></div>
        </div>
        <div id="db-caphint" style="font-size:11px;color:#f39c12;margin-top:8px;display:none;"></div>
        <div style="display:flex;gap:8px;margin-top:10px;align-items:center;">
            <button class="btn btn-success btn-sm" onclick="dbSave()"><i class="fas fa-floppy-disk"></i> Save</button>
            <button class="btn btn-sm" onclick="document.getElementById('db-form').style.display='none'">Cancel</button>
            <span id="db-msg" style="font-size:12px;"></span>
        </div>
    </div>
    <div style="overflow-x:auto;">
        <table class="cfg-table" style="width:100%;font-size:12.5px;border-collapse:collapse;">
            <thead><tr style="color:#7c828c;font-size:10px;text-transform:uppercase;">
                <th style="text-align:left;padding:6px;">Name</th><th style="text-align:left;padding:6px;">Engine</th>
                <th style="text-align:left;padding:6px;">Transport</th><th style="text-align:left;padding:6px;">Target</th>
                <th style="text-align:left;padding:6px;">Node</th><th style="padding:6px;">Status</th><th></th>
            </tr></thead>
            <tbody id="db-tbody"><tr><td colspan="7" style="color:#777;padding:12px;text-align:center;">Loading…</td></tr></tbody>
        </table>
    </div>
</div>
</div><!-- /tab-databases -->
<script>
let DB_ENGINES={}, DB_NODES=[], DB_TARGETS=[];
async function loadDbs(){
  if(!DB_NODES.length){
    const [e,n]=await Promise.all([
      fetch('dbmon.php?api=engines').then(r=>r.json()).catch(()=>({})),
      fetch('dbmon.php?api=nodes').then(r=>r.json()).catch(()=>({}))
    ]);
    DB_ENGINES=(e&&e.engines)||{}; DB_NODES=(n&&n.nodes)||[];
    const es=document.getElementById('db-engine'); if(es) es.innerHTML=Object.keys(DB_ENGINES).map(k=>`<option value="${k}">${DB_ENGINES[k].label}</option>`).join('');
    const ns=document.getElementById('db-node'); if(ns) ns.innerHTML='<option value="">— none —</option>'+DB_NODES.map(x=>`<option value="${x.id}">${dbEsc(x.display_name)} (${dbEsc(x.ip_address||'')})</option>`).join('');
  }
  const r=await fetch('dbmon.php?api=targets&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  const tb=document.getElementById('db-tbody'); const T=(r&&r.targets)||[]; DB_TARGETS=T;
  const rof=document.getElementById('db-replof'); if(rof){ const cur=rof.value; rof.innerHTML='<option value="">— select master —</option>'+T.map(x=>`<option value="${x.id}">${dbEsc(x.display_name)}</option>`).join(''); rof.value=cur; }
  if(!T.length){ tb.innerHTML='<tr><td colspan="7" style="color:#777;padding:14px;text-align:center;">No databases yet — click <b>Add database</b>.</td></tr>'; return; }
  tb.innerHTML=T.map(t=>{
    const stc=t.last_status==='ok'?'#2ecc71':(t.last_status==='error'?'#e74c3c':'#888');
    return `<tr style="border-top:1px solid rgba(255,255,255,.06);">
      <td style="padding:6px;"><b>${dbEsc(t.display_name)}</b></td>
      <td style="padding:6px;">${dbEsc(t.engine)}</td>
      <td style="padding:6px;">${dbEsc(t.transport)}</td>
      <td style="padding:6px;font-family:monospace;color:#9fb0c4;">${dbEsc(t.host)}:${dbEsc(t.port||'')}${t.db_name?('/'+dbEsc(t.db_name)):''}</td>
      <td style="padding:6px;">${t.node_name?dbEsc(t.node_name):'<span style=\"color:#667;\">—</span>'}</td>
      <td style="padding:6px;text-align:center;"><span style="color:${stc};font-weight:700;">${dbEsc((t.last_status||'unknown').toUpperCase())}</span></td>
      <td style="padding:6px;white-space:nowrap;text-align:right;">
        <button class="btn btn-sm" onclick='dbTest(${t.id},this)' title="Test connection"><i class="fas fa-plug"></i></button>
        <button class="btn btn-sm" onclick='dbEdit(${t.id})' title="Edit"><i class="fas fa-pen"></i></button>
        <button class="btn btn-sm" onclick='dbDel(${t.id})' title="Delete"><i class="fas fa-trash"></i></button>
      </td></tr>`;
  }).join('');
}
function dbEsc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function dbEngineChange(){
  const k=document.getElementById('db-engine').value, e=DB_ENGINES[k];
  if(e && !document.getElementById('db-port').value) document.getElementById('db-port').value=e.port;
  dbTransportChange();
}
function dbTransportChange(){
  const k=document.getElementById('db-engine').value, tp=document.getElementById('db-transport').value;
  const caps=(DB_ENGINES[k]||{}).caps||{}; const h=document.getElementById('db-caphint');
  if(tp==='direct' && caps.direct===false){ h.style.display='block'; h.textContent='⚠ '+(caps.direct_reason||'Direct driver not installed — use SSH transport.'); }
  else h.style.display='none';
  dbApplyAutoHost();
}
// Auto-fill Host from the linked node: DIRECT → the node's IP (portal dials it over TCP);
// SSH → 127.0.0.1 (the client runs ON the node, so the DB is local to it). Only overwrites
// when Host is empty or still holds the previous auto value — never clobbers a manual entry.
let dbHostAuto='127.0.0.1';
function dbCurrentNodeIp(){ const id=document.getElementById('db-node').value; const n=DB_NODES.find(x=>String(x.id)===String(id)); return n?(n.ip_address||''):''; }
function dbApplyAutoHost(){
  const tp=document.getElementById('db-transport').value, ip=dbCurrentNodeIp();
  const want = tp==='ssh' ? '127.0.0.1' : (ip || '127.0.0.1');
  const el=document.getElementById('db-host');
  if(el.value==='' || el.value===dbHostAuto) el.value=want;
  dbHostAuto=want;
}
function dbNodeChange(){ dbApplyAutoHost(); }
function dbRoleChange(){ const w=document.getElementById('db-replof-wrap'); if(w) w.style.display=(document.getElementById('db-role').value==='replica')?'':'none'; }
function dbForm(){
  document.getElementById('db-id').value=0; document.getElementById('db-name').value='';
  document.getElementById('db-host').value='127.0.0.1'; dbHostAuto='127.0.0.1'; document.getElementById('db-dbname').value='';
  document.getElementById('db-user').value=''; document.getElementById('db-pass').value='';
  document.getElementById('db-node').value=''; document.getElementById('db-transport').value='direct';
  document.getElementById('db-role').value='standalone'; document.getElementById('db-replof').value=''; dbRoleChange();
  if(document.getElementById('db-engine').options.length) document.getElementById('db-engine').selectedIndex=0;
  document.getElementById('db-port').value=''; dbEngineChange();
  document.getElementById('db-msg').textContent='';
  document.getElementById('db-form').style.display='block';
}
function dbEdit(id){
  const t = DB_TARGETS.find(x=>String(x.id)===String(id)); if(!t) return;   // look up (never embed error text in onclick)
  dbForm();
  document.getElementById('db-id').value=t.id; document.getElementById('db-name').value=t.display_name||'';
  document.getElementById('db-engine').value=t.engine; document.getElementById('db-transport').value=t.transport;
  document.getElementById('db-node').value=t.node_id||''; document.getElementById('db-host').value=t.host||'';
  document.getElementById('db-port').value=t.port||''; document.getElementById('db-dbname').value=t.db_name||'';
  document.getElementById('db-user').value=t.username||''; document.getElementById('db-pass').value='';
  document.getElementById('db-role').value=t.role||'standalone'; document.getElementById('db-replof').value=t.replica_of||''; dbRoleChange();
  dbTransportChange();
}
async function dbSave(){
  const body={ id:+document.getElementById('db-id').value, display_name:document.getElementById('db-name').value,
    engine:document.getElementById('db-engine').value, transport:document.getElementById('db-transport').value,
    node_id:document.getElementById('db-node').value||null, host:document.getElementById('db-host').value,
    port:document.getElementById('db-port').value, db_name:document.getElementById('db-dbname').value,
    username:document.getElementById('db-user').value, enabled:1,
    role:document.getElementById('db-role').value, replica_of:document.getElementById('db-replof').value||null };
  const pw=document.getElementById('db-pass').value; if(pw!=='') body.password=pw;
  const m=document.getElementById('db-msg'); m.style.color='#888'; m.textContent='Saving…';
  const r=await fetch('dbmon.php?api=save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'}));
  if(r.ok){ m.style.color='#2ecc71'; m.textContent='Saved ✓'; setTimeout(()=>{document.getElementById('db-form').style.display='none';loadDbs();},600); }
  else { m.style.color='#e74c3c'; m.textContent=r.error||'Save failed'; }
}
async function dbDel(id){ if(!confirm('Delete this database target?'))return;
  await fetch('dbmon.php?api=delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); loadDbs(); }
async function dbTest(id,btn){
  const old=btn.innerHTML; btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>';
  const r=await fetch('dbmon.php?api=test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'}));
  btn.disabled=false; btn.innerHTML=old;
  if(r.ok){ const p=r.probe||{}; alert('✓ Connected\n\nEngine: '+(p.engine||'')+' '+(p.version||'')+'\nTransport: '+(p.transport||'')+'\nConnections: '+(p.connections||0)+'/'+(p.max_connections||'?')); }
  else alert('✗ Connection failed:\n\n'+(r.error||'unknown'));
  loadDbs();
}
if(new URLSearchParams(location.search).get('tab')==='databases'){ loadDbs(); }
</script>

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB: Containers (Portainer connection)                                  -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-containers" class="tab-panel <?= $tab==='containers'?'active':'' ?>">
<div class="two-col" style="align-items:start;">
<!-- ── LEFT column: infrastructure ── -->
<div>
<div class="glass-card" style="border-color:rgba(13,183,237,.35);">
    <h2 style="color:#0db7ed;"><i class="fab fa-docker"></i> Portainer Connection</h2>
    <p style="font-size:11px;color:#888;margin:0 0 14px;">
        Powers the <a href="containers.php" style="color:#0db7ed;">Containers</a> console (live monitoring,
        logs, AI error-watch &amp; self-heal). The API key is <b>encrypted at rest</b> and never sent to the browser.
    </p>
    <div id="ptn-status" class="conn-status conn-unk" style="margin-bottom:14px;">
        <i class="fas fa-circle-question"></i> <span id="ptn-status-text">Click "Test" to check status.</span>
    </div>
    <form method="post">
        <input type="hidden" name="action" value="save_portainer">
        <div class="form-row">
            <label>Portainer URL</label>
            <input class="form-input" type="text" id="ptn-url" name="portainer_url"
                   value="<?= htmlspecialchars($_portainer_cfg['url']) ?>" placeholder="https://host:9443" autocomplete="off">
        </div>
        <div class="form-row">
            <label>API Key <?php if ($_portainer_haskey): ?><span style="color:#2ecc71;font-weight:400;">(saved — leave blank to keep)</span><?php endif ?></label>
            <input class="form-input" type="password" id="ptn-key" name="portainer_api_key"
                   placeholder="<?= $_portainer_haskey ? '•••••••• stored' : 'Portainer API key (X-API-Key)' ?>" autocomplete="off">
        </div>
        <div class="form-row">
            <label>Verify TLS certificate</label>
            <div class="toggle-wrap">
                <label class="toggle-switch">
                    <input type="checkbox" id="ptn-verify" name="portainer_verify_ssl" <?= $_portainer_cfg['verify']?'checked':'' ?>>
                    <span class="toggle-slider"></span>
                </label>
                <span style="font-size:12px;color:#888;">Off = accept self-signed certs</span>
            </div>
        </div>
        <div class="form-row">
            <label>Host map <span style="color:#555;font-weight:400;">(optional — <code>envname=ip</code> per line, for Edge agents)</span></label>
            <textarea class="form-input" name="portainer_host_map" rows="2" placeholder="prod=10.0.0.5&#10;edge1=192.168.0.7" style="font-family:monospace;"><?= htmlspecialchars($_portainer_cfg['host_map'] ? implode("\n", array_map(fn($k,$v)=>"$k=$v", array_keys($_portainer_cfg['host_map']), $_portainer_cfg['host_map'])) : '') ?></textarea>
        </div>
        <div style="display:flex;gap:8px;margin-top:12px;">
            <button type="button" class="btn btn-primary btn-sm" onclick="testPortainer()"><i class="fas fa-satellite-dish"></i> Test</button>
            <button type="submit" class="btn btn-success btn-sm"><i class="fas fa-floppy-disk"></i> Save</button>
        </div>
    </form>
</div>

<!-- Error Watch & Logs settings -->
<div class="glass-card" style="border-color:rgba(243,156,18,.3);">
    <h2 style="color:var(--warn);"><i class="fas fa-triangle-exclamation"></i> Error Watch &amp; Logs</h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">Drives the n8n error-watch flow (returned via <code>?ep=incidents_config</code>) and log retention.</p>
    <form method="post">
        <input type="hidden" name="action" value="save_container_settings">
        <div class="form-row">
            <label>Enable Error Watch</label>
            <div class="toggle-wrap"><label class="toggle-switch">
                <input type="checkbox" name="error_watch_enabled" <?= cset('error_watch_enabled','1')!=='0'?'checked':'' ?>>
                <span class="toggle-slider"></span></label>
                <span style="font-size:12px;color:#888;">Master switch the flow gates on</span></div>
        </div>
        <div class="form-row">
            <label>Collect container logs</label>
            <div class="toggle-wrap"><label class="toggle-switch">
                <input type="checkbox" name="container_logs_collect" <?= cset('container_logs_collect','1')!=='0'?'checked':'' ?>>
                <span class="toggle-slider"></span></label>
                <span style="font-size:12px;color:#888;">NEURU pulls Docker logs from Portainer every 5&nbsp;min (native — no n8n flow needed). Feeds Error&nbsp;Watch + the log viewer.</span></div>
        </div>
        <div class="form-row">
            <label>Match keywords <span style="color:#555;font-weight:400;">(comma/newline)</span></label>
            <input class="form-input" type="text" name="error_watch_keywords" value="<?= htmlspecialchars(cset('error_watch_keywords','ERROR,ERR,FAILED')) ?>" placeholder="ERROR,ERR,FAILED">
        </div>
        <div class="form-row">
            <label>Ignore lines containing</label>
            <input class="form-input" type="text" name="error_watch_ignore" value="<?= htmlspecialchars(cset('error_watch_ignore','')) ?>" placeholder="healthcheck, debug">
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
            <div class="form-row"><label>Incident retention (days)</label>
                <input class="form-input" type="number" name="error_watch_retention_days" value="<?= (int)cset('error_watch_retention_days','30') ?>" min="1"></div>
            <div class="form-row"><label>Log retention (days)</label>
                <input class="form-input" type="number" name="container_logs_retention_days" value="<?= (int)cset('container_logs_retention_days','7') ?>" min="1"></div>
        </div>
        <div class="form-row">
            <label>Remediation webhook <span style="color:#555;font-weight:400;">(n8n — "Remediate" hand-off)</span></label>
            <input class="form-input" type="text" name="error_watch_remediation_url" value="<?= htmlspecialchars(cset('error_watch_remediation_url','')) ?>" placeholder="http://192.168.0.25:5678/webhook/container-remediate" autocomplete="off">
        </div>
        <div class="form-row">
            <label>Re-analyze webhook <span style="color:#555;font-weight:400;">(force AI re-analysis)</span></label>
            <input class="form-input" type="text" name="error_watch_analyze_url" value="<?= htmlspecialchars(cset('error_watch_analyze_url','')) ?>" placeholder="http://192.168.0.25:5678/webhook/container-analyze" autocomplete="off">
        </div>
        <button type="submit" class="btn btn-success btn-sm" style="margin-top:8px;"><i class="fas fa-floppy-disk"></i> Save Error-Watch Settings</button>
    </form>
</div>
</div><!-- /LEFT column -->

<!-- ── RIGHT column: AI / automation ── -->
<div>
<div class="glass-card" style="border-color:rgba(155,89,182,.3);">
    <h2 style="color:#b07cd6;"><i class="fas fa-key"></i> n8n ↔ Containers API</h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">
        The container n8n flows talk to <code>nm_containers_api.php</code> using the <b>same shared token</b>
        the AI flows already use — <b>no separate key</b>. Present it as header
        <code>X-NetMon-Token</code> (or <code>X-API-Key</code>).
    </p>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <input class="form-input" type="text" id="ctr-key" readonly style="flex:1;min-width:220px;font-family:monospace;font-size:11px;"
               value="<?= htmlspecialchars($_n8n_cfg['inbound_token']) ?>" placeholder="— generate in Integrations &amp; AI —">
        <button type="button" class="btn btn-sm" onclick="copyCtrKey()"><i class="fas fa-copy"></i></button>
    </div>
    <span id="ctr-key-msg" style="font-size:11px;color:#2ecc71;"></span>
    <p style="font-size:11px;color:#666;margin:14px 0 0;border-top:1px solid rgba(255,255,255,.06);padding-top:10px;">
        <i class="fas fa-circle-info"></i> Same token as <a href="net_mon_config.php?tab=integrations" style="color:var(--accent)">Integrations &amp; AI</a>
        (rotate it there). Base API URL for your flows:
        <code style="color:#0db7ed;">&lt;this-host&gt;/nm_containers_api.php?ep=…</code>
    </p>
</div>

<!-- Solution Commander + Knowledge Base webhooks -->
<div class="glass-card" style="border-color:rgba(155,89,182,.3);">
    <h2 style="color:#b07cd6;"><i class="fas fa-wand-magic-sparkles"></i> Solution Commander &amp; KB</h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">Webhook URLs for the interactive AI fix + RAG flows (paste the n8n production URLs).</p>
    <form method="post">
        <input type="hidden" name="action" value="save_fixkb_settings">
        <h3 style="font-size:12px;color:#b07cd6;margin:4px 0 6px;text-transform:uppercase;letter-spacing:1px;">Solution Commander (SSH fix)</h3>
        <div class="form-row"><label>Suggest webhook <span style="color:#555;font-weight:400;">(AI turns: suggest/chat/auto)</span></label>
            <input class="form-input" type="text" name="fix_suggest_url" value="<?= htmlspecialchars(cset('fix_suggest_url','')) ?>" placeholder="http://192.168.0.25:5678/webhook/container-fix-suggest" autocomplete="off"></div>
        <div class="form-row"><label>Execute webhook <span style="color:#555;font-weight:400;">(runs the approved command over SSH)</span></label>
            <input class="form-input" type="text" name="fix_webhook_url" value="<?= htmlspecialchars(cset('fix_webhook_url','')) ?>" placeholder="http://192.168.0.25:5678/webhook/container-fix-exec" autocomplete="off"></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
            <div class="form-row"><label>SSH user <span style="color:#555;font-weight:400;">(optional — n8n cred may handle it)</span></label>
                <input class="form-input" type="text" name="fix_ssh_user" value="<?= htmlspecialchars(cset('fix_ssh_user','')) ?>" autocomplete="off"></div>
            <div class="form-row"><label>SSH password <?php if ($_fix_haspass): ?><span style="color:#2ecc71;font-weight:400;">(saved)</span><?php endif ?></label>
                <input class="form-input" type="password" name="fix_ssh_password" placeholder="<?= $_fix_haspass?'•••••• stored':'optional (encrypted)' ?>" autocomplete="off"></div>
        </div>
        <h3 style="font-size:12px;color:#b07cd6;margin:14px 0 6px;text-transform:uppercase;letter-spacing:1px;">Knowledge Base (RAG)</h3>
        <div class="form-row"><label>Enable capture + recall</label>
            <div class="toggle-wrap"><label class="toggle-switch">
                <input type="checkbox" name="kb_enabled" <?= cset('kb_enabled','1')!=='0'?'checked':'' ?>>
                <span class="toggle-slider"></span></label><span style="font-size:12px;color:#888;">Snapshot resolved fixes &amp; recall similar ones</span></div></div>
        <div class="form-row"><label>KB ingest webhook <span style="color:#555;font-weight:400;">(embed into pgvector)</span></label>
            <input class="form-input" type="text" name="kb_ingest_url" value="<?= htmlspecialchars(cset('kb_ingest_url','')) ?>" placeholder="http://192.168.0.25:5678/webhook/kb-ingest" autocomplete="off"></div>
        <div class="form-row"><label>KB search webhook <span style="color:#555;font-weight:400;">(vector search)</span></label>
            <input class="form-input" type="text" name="kb_search_url" value="<?= htmlspecialchars(cset('kb_search_url','')) ?>" placeholder="http://192.168.0.25:5678/webhook/kb-search" autocomplete="off"></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
            <div class="form-row"><label>Top-K recall</label><input class="form-input" type="number" name="kb_top_k" value="<?= (int)cset('kb_top_k','3') ?>" min="1" max="10"></div>
            <div class="form-row"><label>Min score (cosine)</label><input class="form-input" type="number" step="0.01" name="kb_min_score" value="<?= htmlspecialchars(cset('kb_min_score','0.5')) ?>" min="0" max="1"></div>
        </div>
        <div class="form-row"><label>Books/Docs search webhook <span style="color:#555;font-weight:400;">(optional runbook RAG)</span></label>
            <input class="form-input" type="text" name="books_search_url" value="<?= htmlspecialchars(cset('books_search_url','')) ?>" placeholder="http://192.168.0.25:5678/webhook/books-search" autocomplete="off"></div>
        <input type="hidden" name="books_top_k" value="<?= (int)cset('books_top_k','3') ?>">
        <button type="submit" class="btn btn-success btn-sm" style="margin-top:8px;"><i class="fas fa-floppy-disk"></i> Save Fix &amp; KB Settings</button>
    </form>
</div>
</div><!-- /RIGHT column -->
</div><!-- /two-col -->

<!-- Full-width footer -->
<div class="glass-card">
    <h2><i class="fas fa-circle-info" style="color:var(--accent);"></i> About the Containers module</h2>
    <p style="font-size:12.5px;color:#9aa;line-height:1.6;margin:0;">
        <b>Live monitoring</b> reads Portainer in real time (no n8n needed): overview, detail, live charts, volumes.<br><br>
        <b>Logs, AI Error-Watch &amp; Solution Commander</b> reuse your existing n8n flows, re-pointed to this portal's API.
    </p>
</div>
</div><!-- /tab-containers -->

<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- TAB: L2 Switches (TP-Link Easy Smart — no SNMP/syslog, web-UI scrape)    -->
<!-- ══════════════════════════════════════════════════════════════════════ -->
<div id="tab-switches" class="tab-panel <?= $tab==='switches'?'active':'' ?>">
<div class="glass-card" style="border-color:rgba(77,163,255,.3);">
    <h2 style="display:flex;justify-content:space-between;align-items:center;">
        <span><i class="fas fa-ethernet" style="color:#4da3ff;"></i> Unmanaged Switches <span style="font-size:11px;font-weight:400;color:#888;">— TP-Link Easy Smart (TL-SG10xE), no SNMP/syslog</span></span>
        <span><a class="btn btn-sm" href="l2switch.php" style="margin-right:6px;"><i class="fas fa-up-right-from-square"></i> Open monitor</a>
        <button class="btn btn-sm" onclick="l2Form(0)"><i class="fas fa-plus"></i> Add switch</button></span>
    </h2>
    <p style="font-size:11px;color:#888;margin:0 0 12px;">
        These switches have no SNMP and no remote syslog, so NEURU logs into their web UI and scrapes
        <b>Port Statistics</b> every 2&nbsp;min — giving per-port <b>packets/sec</b>, link state, and
        <b>bad-packet</b>/<b>link-flap</b> alerts. Passwords are <b>encrypted at rest</b> (AES-256-GCM).
        Counters are packets (not bytes), so rates are pps, not Mbps.
    </p>
    <div id="l2-form" style="display:none;background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:12px;">
        <input type="hidden" id="l2-id" value="0">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;">
            <div><label style="font-size:10px;color:#aaa;">Name</label><input class="form-input" id="l2-name" placeholder="Core Switch"></div>
            <div><label style="font-size:10px;color:#aaa;">Host / IP</label><input class="form-input" id="l2-host" placeholder="192.168.0.252"></div>
            <div><label style="font-size:10px;color:#aaa;">Port</label><input class="form-input" id="l2-port" type="number" value="80" style="width:80px;"></div>
            <div><label style="font-size:10px;color:#aaa;">Username</label><input class="form-input" id="l2-user" value="admin"></div>
            <div><label style="font-size:10px;color:#aaa;">Model</label><input class="form-input" id="l2-model" placeholder="TL-SG108E"></div>
            <div><label style="font-size:10px;color:#aaa;">Bad-pkt alert (pps)</label><input class="form-input" id="l2-thr" type="number" step="0.5" value="1" style="width:90px;"></div>
            <div><label style="font-size:10px;color:#aaa;">Enabled</label>
                <select class="form-select" id="l2-en"><option value="1">Yes</option><option value="0">No</option></select></div>
        </div>
        <div style="margin-top:8px;"><label style="font-size:10px;color:#aaa;" id="l2-pwlbl">Password</label>
            <input class="form-input" id="l2-pass" type="password" placeholder="••••••••" style="font-family:monospace;"></div>
        <div style="display:flex;gap:8px;margin-top:10px;align-items:center;">
            <button class="btn btn-success btn-sm" onclick="l2Save()"><i class="fas fa-floppy-disk"></i> Save</button>
            <button class="btn btn-sm" onclick="l2Test()"><i class="fas fa-plug"></i> Test</button>
            <button class="btn btn-sm" onclick="document.getElementById('l2-form').style.display='none'">Cancel</button>
            <span id="l2-msg" style="font-size:12px;"></span>
        </div>
    </div>
    <div style="overflow-x:auto;">
        <table class="cfg-table" style="width:100%;font-size:12.5px;border-collapse:collapse;">
            <thead><tr style="color:#7c828c;font-size:10px;text-transform:uppercase;">
                <th style="text-align:left;padding:6px;">Name</th><th style="text-align:left;padding:6px;">Host</th>
                <th style="text-align:left;padding:6px;">Model</th><th style="padding:6px;">Enabled</th>
                <th style="padding:6px;">Status</th><th style="text-align:left;padding:6px;">Last poll</th><th></th>
            </tr></thead>
            <tbody id="l2-tbody"><tr><td colspan="7" style="color:#777;padding:12px;text-align:center;">Loading…</td></tr></tbody>
        </table>
    </div>
</div>
</div><!-- /tab-switches -->

<script>
// ── L2 Switches (TP-Link Easy Smart) — reuses l2switch.php engine endpoints ──
function _l2Esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
window._L2 = [];
async function loadL2(){
    const r = await fetch('l2switch.php?api=data').then(r=>r.json()).catch(()=>null);
    const tb = document.getElementById('l2-tbody'); if(!tb) return;
    if(!r||!r.ok){ tb.innerHTML='<tr><td colspan="7" style="color:#e74c3c;padding:12px;text-align:center;">Could not load.</td></tr>'; return; }
    window._L2 = r.switches||[];
    tb.innerHTML = window._L2.length ? window._L2.map(s=>{
        const st = s.last_status==='ok' ? '<span style="color:#2ecc71;">● OK</span>'
                 : s.last_status==='error' ? `<span style="color:#e74c3c;" title="${_l2Esc(s.last_error)}">● Error</span>`
                 : '<span style="color:#888;">—</span>';
        return `<tr>
            <td style="padding:6px;"><b>${_l2Esc(s.name)}</b></td>
            <td style="padding:6px;">${_l2Esc(s.host)}:${s.port}</td>
            <td style="padding:6px;color:#9aa;">${_l2Esc(s.model||'')}</td>
            <td style="padding:6px;text-align:center;">${s.enabled?'<span style="color:#2ecc71;">Yes</span>':'<span style="color:#888;">No</span>'}</td>
            <td style="padding:6px;text-align:center;">${st}</td>
            <td style="padding:6px;color:#9aa;">${_l2Esc(s.last_poll||'never')}</td>
            <td style="padding:6px;text-align:right;white-space:nowrap;">
                <button class="btn btn-sm" onclick="l2Form(${s.id})"><i class="fas fa-pen"></i></button>
                <button class="btn btn-sm" onclick="l2Del(${s.id})" style="color:#f0a59d;"><i class="fas fa-trash"></i></button></td>
        </tr>`;
    }).join('') : '<tr><td colspan="7" style="color:#777;padding:12px;text-align:center;">No switches yet — click “Add switch”.</td></tr>';
}
function l2Form(id){
    const s = window._L2.find(x=>x.id==id);
    document.getElementById('l2-id').value = s?s.id:0;
    document.getElementById('l2-name').value = s?s.name:'';
    document.getElementById('l2-host').value = s?s.host:'';
    document.getElementById('l2-port').value = s?s.port:80;
    document.getElementById('l2-user').value = s?s.username:'admin';
    document.getElementById('l2-model').value = s?(s.model||''):'';
    document.getElementById('l2-thr').value = s?s.err_threshold_pps:1;
    document.getElementById('l2-en').value = s?String(s.enabled):'1';
    document.getElementById('l2-pass').value = '';
    document.getElementById('l2-pwlbl').textContent = s?'Password (blank = unchanged)':'Password';
    document.getElementById('l2-msg').textContent='';
    document.getElementById('l2-form').style.display='block';
}
function _l2Body(extra){
    const p=new URLSearchParams();
    p.set('id',document.getElementById('l2-id').value);
    p.set('name',document.getElementById('l2-name').value);
    p.set('host',document.getElementById('l2-host').value);
    p.set('port',document.getElementById('l2-port').value);
    p.set('username',document.getElementById('l2-user').value);
    p.set('model',document.getElementById('l2-model').value);
    p.set('password',document.getElementById('l2-pass').value);
    p.set('err_threshold_pps',document.getElementById('l2-thr').value);
    p.set('enabled',document.getElementById('l2-en').value);
    for(const k in extra) p.set(k,extra[k]);
    return p.toString();
}
async function l2Test(){
    const m=document.getElementById('l2-msg'); m.style.color='#9aa'; m.textContent='Testing…';
    const r=await fetch('l2switch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:_l2Body({action:'test'})}).then(r=>r.json()).catch(()=>null);
    if(r&&r.ok){ m.style.color='#2ecc71'; m.textContent='✓ Connected — '+r.ports+' ports'; }
    else { m.style.color='#e74c3c'; m.textContent='✗ '+(r?r.error:'failed'); }
}
async function l2Save(){
    const m=document.getElementById('l2-msg'); m.style.color='#9aa'; m.textContent='Saving…';
    const r=await fetch('l2switch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:_l2Body({action:'save'})}).then(r=>r.json()).catch(()=>null);
    if(r&&r.ok){ document.getElementById('l2-form').style.display='none'; loadL2(); }
    else { m.style.color='#e74c3c'; m.textContent='✗ '+(r?r.error:'failed'); }
}
async function l2Del(id){
    if(!confirm('Delete this switch and its history?')) return;
    await fetch('l2switch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'action=delete&id='+id});
    loadL2();
}
<?php if ($tab==='switches'): ?>document.addEventListener('DOMContentLoaded',loadL2);<?php endif; ?>
</script>

<script>
// ── Edit form toggle ──────────────────────────────────────────────────────────
function toggleEditForm(nodeId) {
    document.querySelectorAll('[id^="edit-form-"]').forEach(el => {
        if (el.id !== 'edit-form-' + nodeId) el.style.display = 'none';
    });
    const el = document.getElementById('edit-form-' + nodeId);
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

// ── Auto-locate node coordinates from its IP (GeoIP — public IPs only) ─────────
async function geoLocate(btn, ip){
    const f=btn.closest('form'); const msg=btn.parentElement.querySelector('.geo-msg');
    if(!ip){ msg.style.color='#e74c3c'; msg.textContent='No IP on this node'; return; }
    msg.style.color='#9aa'; msg.textContent='Locating…';
    const r=await fetch('net_mon_config.php?api=node_geoip&ip='+encodeURIComponent(ip)).then(r=>r.json()).catch(()=>null);
    if(r&&r.ok){
        f.querySelector('.geo-lat').value=r.lat; f.querySelector('.geo-lon').value=r.lon;
        if(!f.querySelector('.geo-city').value) f.querySelector('.geo-city').value=r.city||'';
        if(!f.querySelector('.geo-country').value) f.querySelector('.geo-country').value=r.country||'';
        msg.style.color='#2ecc71'; msg.textContent='✓ '+[r.city,r.country].filter(Boolean).join(', ');
    } else { msg.style.color='#e74c3c'; msg.textContent='✗ '+(r?r.error:'failed'); }
}

// ── Pick node coordinates by clicking a map (fills lat/lon on the node form) ──
let _pmMap=null,_pmMarker=null,_pmForm=null,_pmLL=null;
function pickOnMap(btn){
    _pmForm=btn.closest('form');
    let bg=document.getElementById('pm-bg');
    if(!bg){
        bg=document.createElement('div'); bg.id='pm-bg';
        bg.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;display:flex;align-items:center;justify-content:center;';
        bg.innerHTML='<div style="width:680px;max-width:94vw;background:#0d1622;border:1px solid #2a3a4d;border-radius:12px;padding:14px;">'
            +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;"><b style="color:#cfe4ff;"><i class="fas fa-map-pin"></i> Click the map where this node is located</b>'
            +'<span style="font-size:12px;color:#9aa;" id="pm-coord">—</span></div>'
            +'<div id="pm-map" style="height:420px;border-radius:8px;"></div>'
            +'<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px;">'
            +'<button type="button" class="btn btn-sm" onclick="document.getElementById(\'pm-bg\').style.display=\'none\'">Cancel</button>'
            +'<button type="button" class="btn btn-success btn-sm" onclick="pmUse()"><i class="fas fa-check"></i> Use this location</button></div></div>';
        document.body.appendChild(bg);
    }
    bg.style.display='flex';
    const lat=parseFloat(_pmForm.querySelector('.geo-lat').value), lon=parseFloat(_pmForm.querySelector('.geo-lon').value);
    const has=(!isNaN(lat)&&!isNaN(lon)), c=has?[lat,lon]:[18.4655,-66.1057];
    setTimeout(()=>{
        if(!_pmMap){
            _pmMap=L.map('pm-map').setView(c,has?13:11);
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:19}).addTo(_pmMap);
            _pmMap.on('click',e=>pmSet(e.latlng.lat,e.latlng.lng));
        } else { _pmMap.setView(c,has?13:11); }
        _pmMap.invalidateSize();
        if(_pmMarker){ _pmMap.removeLayer(_pmMarker); _pmMarker=null; } _pmLL=null;
        document.getElementById('pm-coord').textContent='—';
        if(has) pmSet(lat,lon);
    },70);
}
function pmSet(lat,lon){
    _pmLL=[lat,lon];
    if(_pmMarker) _pmMarker.setLatLng(_pmLL); else _pmMarker=L.circleMarker(_pmLL,{radius:8,color:'#2ecc71',fillColor:'#2ecc71',fillOpacity:.85,weight:2}).addTo(_pmMap);
    document.getElementById('pm-coord').textContent=lat.toFixed(5)+', '+lon.toFixed(5);
}
function pmUse(){
    if(_pmLL&&_pmForm){ _pmForm.querySelector('.geo-lat').value=_pmLL[0].toFixed(6); _pmForm.querySelector('.geo-lon').value=_pmLL[1].toFixed(6); }
    document.getElementById('pm-bg').style.display='none';
}

// ── Test SNMP (existing node edit form) ───────────────────────────────────────
async function testSnmp(ip, community, version, nodeId) {
    const el = document.getElementById('snmp-test-' + nodeId);
    if (el) el.innerHTML = '<span class="spinner"></span>';
    const r = await fetch(`net_mon_config.php?api=test_snmp&ip=${encodeURIComponent(ip)}&community=${encodeURIComponent(community)}&version=${encodeURIComponent(version)}`).then(r=>r.json()).catch(()=>({ok:false,err:'Network error'}));
    if (el) el.innerHTML = r.ok
        ? `<span style="color:var(--up)"><i class="fas fa-check-circle"></i> ${escHtml(r.sysName)}</span>`
        : `<span style="color:var(--down)"><i class="fas fa-times-circle"></i> ${escHtml(r.err)}</span>`;
}

// ── Test SNMP (new device form) ───────────────────────────────────────────────
async function testSnmpNew() {
    const ip   = document.getElementById('anf-ip')?.value.trim();
    const comm = document.getElementById('anf-comm')?.value.trim();
    const ver  = document.getElementById('anf-ver')?.value;
    const el   = document.getElementById('snmp-test-new');
    if (!ip || !comm) { if(el) el.innerHTML='<span style="color:var(--warn)">Enter IP and community first</span>'; return; }
    if (el) el.innerHTML = '<span class="spinner"></span>';
    const r = await fetch(`net_mon_config.php?api=test_snmp&ip=${encodeURIComponent(ip)}&community=${encodeURIComponent(comm)}&version=${encodeURIComponent(ver)}`).then(r=>r.json()).catch(()=>({ok:false,err:'Network error'}));
    if (el) {
        if (r.ok) {
            el.innerHTML = `<span style="color:var(--up)"><i class="fas fa-check-circle"></i> ${escHtml(r.sysName)}</span>`;
            // Auto-fill display name if empty
            const dn = document.getElementById('anf-display');
            if (dn && !dn.value) dn.value = r.sysName;
        } else {
            el.innerHTML = `<span style="color:var(--down)"><i class="fas fa-times-circle"></i> ${escHtml(r.err)}</span>`;
        }
    }
}

// ── Poller test run ───────────────────────────────────────────────────────────
function testPoller() {
    const out = document.getElementById('poller-test-out');
    out.style.display = 'block';
    out.textContent   = 'Running poller… (this may take 10-30 seconds)';
    fetch('net_mon_config.php?api=run_poller', { credentials:'same-origin' })
        .then(r => r.json())
        .then(d => { out.textContent = d.output || d.err || 'Done.'; })
        .catch(e => { out.textContent = 'Error: ' + e.message; });
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function showTab(t) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('tab-'+t)?.classList.add('active');
    document.querySelectorAll('.tab-btn').forEach(b => {
        if (b.getAttribute('onclick')===`showTab('${t}')`) b.classList.add('active');
    });
    history.replaceState(null,'','net_mon_config.php?tab='+t);
}

// ── Connections (manual topology wiring) ──────────────────────────────────────
function _lkEsc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function _lkNodeOpts(){ return '<option value="">— select —</option>'+(window._LK_NODES||[]).map(n=>`<option value="${n.id}">${_lkEsc(n.name)} (${_lkEsc(n.ip)})</option>`).join(''); }
function _lkInit(){ ['lk-a-node','lk-z-node','dmy-node'].forEach(id=>{ const el=document.getElementById(id); if(el&&!el.dataset.filled){ el.innerHTML=_lkNodeOpts(); el.dataset.filled='1'; } }); }
async function lkLoadIf(side){
    const nid=document.getElementById('lk-'+side+'-node').value, sel=document.getElementById('lk-'+side+'-if');
    sel.innerHTML='<option value="">— whole device —</option>';
    if(!nid) return;
    try{ const r=await fetch('net_mon_config.php?api=get_node_ifaces&node_id='+nid).then(r=>r.json());
        sel.innerHTML='<option value="">— whole device —</option>'+(r.ifaces||[]).map(i=>`<option value="${i.id}">${_lkEsc(i.display_name||i.if_name)}${i.if_ip_address?' ('+_lkEsc(i.if_ip_address)+')':''}${i.is_dummy==1?' [virtual]':''}</option>`).join('');
    }catch(e){}
}
async function loadLinks(){
    _lkInit();
    loadAutoLinks();
    const tb=document.getElementById('lk-tbody'); if(!tb) return;
    try{ const r=await fetch('net_mon_config.php?api=links_list').then(r=>r.json()); const L=r.links||[];
        if(!L.length){ tb.innerHTML='<tr><td colspan="6" style="color:#777;padding:14px;text-align:center;">No manual connections yet — add one above.</td></tr>'; return; }
        tb.innerHTML=L.map(l=>{
            const aif=l.a_if?` · <span style="color:#7fd1ff;">${_lkEsc(l.a_if)}</span>`:'';
            const zif=l.z_if?` · <span style="color:#7fd1ff;">${_lkEsc(l.z_if)}</span>`:'';
            return `<tr style="border-top:1px solid #1d222b;">
                <td style="padding:6px 8px;">${_lkEsc(l.a_node)}${aif}</td>
                <td style="padding:6px 8px;text-align:center;color:#2ecc71;">↔</td>
                <td style="padding:6px 8px;">${_lkEsc(l.z_node)}${zif}</td>
                <td style="padding:6px 8px;color:#aaa;">${l.traffic_side==='a'?'A side':'Z side'}</td>
                <td style="padding:6px 8px;color:#888;">${_lkEsc(l.label||'')}</td>
                <td style="padding:6px 8px;text-align:right;"><button class="btn btn-sm" style="border-color:#e74c3c;color:#e74c3c;" onclick="deleteLink(${l.id})"><i class="fas fa-trash"></i></button></td>
            </tr>`;
        }).join('');
    }catch(e){ tb.innerHTML='<tr><td colspan="6" style="color:#e74c3c;padding:14px;text-align:center;">Error loading.</td></tr>'; }
}
async function saveLink(){
    const body={ a_node_id:+document.getElementById('lk-a-node').value, a_iface_id:+document.getElementById('lk-a-if').value||0,
                 z_node_id:+document.getElementById('lk-z-node').value, z_iface_id:+document.getElementById('lk-z-if').value||0,
                 traffic_side:document.getElementById('lk-side').value, label:document.getElementById('lk-label').value.trim() };
    if(!body.a_node_id||!body.z_node_id||body.a_node_id===body.z_node_id){ alert('Pick two different devices.'); return; }
    const r=await fetch('net_mon_config.php?api=link_save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json()).catch(()=>({ok:false}));
    if(r.ok){ document.getElementById('lk-label').value=''; loadLinks(); } else alert(r.err||'Save failed');
}
async function deleteLink(id){
    if(!confirm('Delete this connection?')) return;
    await fetch('net_mon_config.php?api=link_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
    loadLinks();
}

// ── Auto-discovered connections (computed live by the map) ────────────────────
function _ifLbl(o){ return o ? (_lkEsc(o.name)+(o.ip?` <span style="color:#666">${_lkEsc(o.ip)}</span>`:'')) : '<span style="color:#666">whole device</span>'; }
function _fmtRate(b){ b=+b||0; if(b>=1e6) return (b/1e6).toFixed(1)+' MB/s'; if(b>=1e3) return (b/1e3).toFixed(1)+' KB/s'; return b.toFixed(0)+' B/s'; }
async function loadAutoLinks(){
    const tb=document.getElementById('auto-tbody'); if(!tb) return;
    tb.innerHTML='<tr><td colspan="6" style="color:#777;padding:14px;text-align:center;">Loading…</td></tr>';
    try{
        const [topo,hid]=await Promise.all([
            fetch('net_mon_map.php?api=topo').then(r=>r.json()),
            fetch('net_mon_config.php?api=links_hidden').then(r=>r.json())
        ]);
        const names={}; (topo.nodes||[]).forEach(n=>names[n.id]=n.name);
        const auto=(topo.links||[]).filter(l=>l.kind==='gateway'||l.kind==='subnet');
        if(!auto.length){ tb.innerHTML='<tr><td colspan="6" style="color:#777;padding:14px;text-align:center;">No auto-discovered links right now.</td></tr>'; }
        else tb.innerHTML=auto.map(l=>{
            const tlabel=l.kind==='gateway'?'Gateway':'Subnet '+_lkEsc(l.subnet);
            return `<tr style="border-top:1px solid #1d222b;">
                <td style="padding:6px 8px;">${_lkEsc(names[l.source]||('#'+l.source))} · ${_ifLbl(l.src_if)}</td>
                <td style="padding:6px 8px;text-align:center;color:#4da3ff;">↔</td>
                <td style="padding:6px 8px;">${_lkEsc(names[l.target]||('#'+l.target))} · ${_ifLbl(l.tgt_if)}</td>
                <td style="padding:6px 8px;color:#888;">${tlabel}</td>
                <td style="padding:6px 8px;color:#aaa;font-family:monospace;font-size:11px;">↓${_fmtRate(l.in_rate)} ↑${_fmtRate(l.out_rate)}</td>
                <td style="padding:6px 8px;text-align:right;"><button class="btn btn-sm" style="border-color:#e67e22;color:#e67e22;" title="Remove this connection" onclick="hideAuto(${l.source},${l.target})"><i class="fas fa-eye-slash"></i> Remove</button></td>
            </tr>`;
        }).join('');
        // Hidden / removed connections
        const H=hid.hidden||[]; const hw=document.getElementById('hidden-wrap'), hl=document.getElementById('hidden-list');
        if(H.length){ hw.style.display='block';
            hl.innerHTML=H.map(h=>`<span style="display:inline-flex;align-items:center;gap:6px;background:rgba(231,76,60,.1);border:1px solid rgba(231,76,60,.3);border-radius:20px;padding:3px 10px;font-size:12px;">
                ${_lkEsc(h.a_node)} ↔ ${_lkEsc(h.z_node)}
                <button class="btn btn-sm" style="border:none;background:none;color:#2ecc71;padding:0;" title="Restore" onclick="unhideAuto(${h.a_node_id},${h.z_node_id})"><i class="fas fa-rotate-left"></i></button></span>`).join('');
        } else { hw.style.display='none'; hl.innerHTML=''; }
    }catch(e){ tb.innerHTML='<tr><td colspan="6" style="color:#e74c3c;padding:14px;text-align:center;">Error loading auto links.</td></tr>'; }
}
async function hideAuto(a,z){
    await fetch('net_mon_config.php?api=link_hide',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({a_node_id:a,z_node_id:z})});
    loadAutoLinks();
}
async function unhideAuto(a,z){
    await fetch('net_mon_config.php?api=link_unhide',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({a_node_id:a,z_node_id:z})});
    loadAutoLinks();
}
async function addDummy(){
    const node_id=+document.getElementById('dmy-node').value, name=document.getElementById('dmy-name').value.trim(), msg=document.getElementById('dmy-msg');
    if(!node_id||!name){ alert('Pick a device and enter an interface name.'); return; }
    const r=await fetch('net_mon_config.php?api=iface_add_dummy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id,name})}).then(r=>r.json()).catch(()=>({ok:false}));
    if(r.ok){ msg.textContent='Added "'+name+'" — now selectable as an interface.'; document.getElementById('dmy-name').value=''; setTimeout(()=>msg.textContent='',4000); } else alert(r.err||'Failed');
}
if(new URLSearchParams(location.search).get('tab')==='links') loadLinks();

// ── Integrations & AI (Graylog + n8n) ─────────────────────────────────────────
function _esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
async function testGraylog(){
    const box=document.getElementById('gl-status'), txt=document.getElementById('gl-status-text');
    box.className='conn-status conn-unk'; txt.textContent='Testing…';
    const url=encodeURIComponent(document.getElementById('gl-url').value.trim());
    const tok=encodeURIComponent(document.getElementById('gl-token').value.trim());
    try{ const r=await fetch(`net_mon_config.php?api=graylog_test&url=${url}&token=${tok}`).then(r=>r.json());
        if(r.ok){ box.className='conn-status conn-ok'; txt.innerHTML=`<i class="fas fa-check-circle"></i> Connected — Graylog ${_esc(r.version)} ${r.lifecycle?('('+_esc(r.lifecycle)+')'):''}`; }
        else { box.className='conn-status conn-bad'; txt.innerHTML=`<i class="fas fa-times-circle"></i> ${_esc(r.err||'Failed')}`; }
    }catch(e){ box.className='conn-status conn-bad'; txt.textContent='Request failed'; }
}
async function testSmokeping(){
    const box=document.getElementById('sp-status'), txt=document.getElementById('sp-status-text');
    box.className='conn-status conn-unk'; txt.textContent='Testing…';
    const url=encodeURIComponent(document.getElementById('sp-url').value.trim());
    try{ const r=await fetch(`net_mon_config.php?api=smokeping_test&url=${url}`).then(r=>r.json());
        if(r.ok){ box.className='conn-status conn-ok'; txt.innerHTML=`<i class="fas fa-check-circle"></i> Reachable (HTTP ${r.code})${r.smokeping?' — Smokeping detected':''}`; }
        else { box.className='conn-status conn-bad'; txt.innerHTML=`<i class="fas fa-times-circle"></i> ${_esc(r.err||'Failed')}`; }
    }catch(e){ box.className='conn-status conn-bad'; txt.textContent='Request failed'; }
}
async function saveSmokeping(){
    const fd=new FormData();
    fd.append('smokeping_url', document.getElementById('sp-url').value.trim());
    fd.append('smokeping_enabled', document.getElementById('sp-enabled').checked?'1':'0');
    fd.append('smokeping_host_ip', document.getElementById('sp-host').value.trim());
    fd.append('smokeping_container', document.getElementById('sp-container').value.trim());
    fd.append('smokeping_targets_path', document.getElementById('sp-path').value.trim());
    fd.append('smokeping_data_path', document.getElementById('sp-data').value.trim());
    fd.append('smokeping_reload_cmd', document.getElementById('sp-reload').value.trim());
    fd.append('smokeping_alerts_enabled', document.getElementById('sp-al-en').checked?'1':'0');
    fd.append('smokeping_alert_sustain', document.getElementById('sp-sustain').value.trim());
    fd.append('smokeping_alert_url', document.getElementById('sp-alurl').value.trim());
    fd.append('rtt_warn', document.getElementById('sp-rw').value.trim());
    fd.append('rtt_crit', document.getElementById('sp-rc').value.trim());
    fd.append('loss_warn', document.getElementById('sp-lw').value.trim());
    fd.append('loss_crit', document.getElementById('sp-lc').value.trim());
    const r=await fetch('net_mon_config.php?api=smokeping_save',{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false}));
    const box=document.getElementById('sp-status'), txt=document.getElementById('sp-status-text');
    box.className=r.ok?'conn-status conn-ok':'conn-status conn-bad';
    txt.innerHTML=r.ok?'<i class="fas fa-check-circle"></i> Saved.':'<i class="fas fa-times-circle"></i> Save failed';
    const lbl=document.getElementById('sp-en-lbl'), on=document.getElementById('sp-enabled').checked;
    lbl.textContent=on?'Enabled':'Disabled'; lbl.style.color=on?'var(--up)':'var(--down)';
}
let _phServers = [];
function phStatus(cls,html){ const b=document.getElementById('ph-status'),t=document.getElementById('ph-status-text');
    b.style.display='flex'; b.className='conn-status '+cls; t.innerHTML=html; }
function _phEsc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
async function reloadPiholes(){
    const r=await fetch('net_mon_config.php?api=pihole_list').then(r=>r.json()).catch(()=>({ok:false}));
    if(!r.ok) return; _phServers=r.servers||[];
    const tb=document.getElementById('ph-tbody');
    tb.innerHTML = _phServers.length ? _phServers.map(s=>{
        const st = s.enabled ? (s.has_pw?['conn-ok','enabled']:['conn-unk','no password']) : ['conn-off','disabled'];
        return `<tr data-id="${s.id}">
            <td><b>${_phEsc(s.name)}</b></td>
            <td class="mono" style="font-size:11px;">${_phEsc(s.url)}</td>
            <td>${s.verify?'verify':'<span style="color:#888;">skip</span>'}</td>
            <td><span class="conn-status ${st[0]}" style="padding:2px 8px;font-size:10px;">${st[1]}</span></td>
            <td style="text-align:right;white-space:nowrap;">
                <button class="btn btn-sm" title="Test" onclick="testPihole(${s.id},this)"><i class="fas fa-satellite-dish"></i></button>
                <button class="btn btn-sm" title="Edit" onclick="editPihole(${s.id})"><i class="fas fa-pen"></i></button>
                <button class="btn btn-sm btn-danger" title="Delete" onclick="deletePihole(${s.id},'${_phEsc(s.name)}')"><i class="fas fa-trash"></i></button>
            </td></tr>`;
    }).join('') : '<tr><td colspan="5" style="color:#888;text-align:center;padding:14px;">No Pi-holes yet — add one below.</td></tr>';
}
function resetPiholeForm(){
    document.getElementById('ph-id').value='0';
    document.getElementById('ph-name').value=''; document.getElementById('ph-url').value=''; document.getElementById('ph-password').value='';
    document.getElementById('ph-enabled').checked=true; document.getElementById('ph-verify').checked=false;
    document.getElementById('ph-form-title').textContent='Add a Pi-hole';
    document.getElementById('ph-save-lbl').textContent='Add Pi-hole';
    document.getElementById('ph-pw-hint').textContent='(required)';
    document.getElementById('ph-cancel').style.display='none';
    document.getElementById('ph-status').style.display='none';
}
async function editPihole(id){
    // Rows can be server-rendered (so _phServers may be empty on first load) AND the DB returns id as a
    // STRING while the onclick passes an int — so fetch-if-needed + compare numerically, else Edit no-ops.
    id=Number(id);
    let s=_phServers.find(x=>Number(x.id)===id);
    if(!s){ await reloadPiholes(); s=_phServers.find(x=>Number(x.id)===id); }
    if(!s) return;
    document.getElementById('ph-id').value=s.id;
    document.getElementById('ph-name').value=s.name; document.getElementById('ph-url').value=s.url;
    document.getElementById('ph-password').value=''; document.getElementById('ph-password').placeholder=s.has_pw?'•••••••• (unchanged)':'Pi-hole admin password';
    document.getElementById('ph-pw-hint').textContent=s.has_pw?'(leave blank to keep)':'(required)';
    document.getElementById('ph-enabled').checked=s.enabled; document.getElementById('ph-verify').checked=s.verify;
    document.getElementById('ph-form-title').textContent='Edit "'+s.name+'"';
    document.getElementById('ph-save-lbl').textContent='Save changes';
    document.getElementById('ph-cancel').style.display='';
    document.getElementById('ph-form').scrollIntoView({behavior:'smooth',block:'nearest'});
}
async function savePihole(){
    const url=document.getElementById('ph-url').value.trim();
    if(!url){ phStatus('conn-bad','<i class="fas fa-times-circle"></i> Address is required'); return; }
    const fd=new FormData();
    fd.append('id', document.getElementById('ph-id').value);
    fd.append('name', document.getElementById('ph-name').value.trim());
    fd.append('url', url);
    fd.append('password', document.getElementById('ph-password').value);   // blank = keep on edit
    fd.append('verify_tls', document.getElementById('ph-verify').checked?'1':'0');
    fd.append('enabled', document.getElementById('ph-enabled').checked?'1':'0');
    const r=await fetch('net_mon_config.php?api=pihole_server_save',{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false}));
    if(r.ok){ phStatus('conn-ok','<i class="fas fa-check-circle"></i> Saved. Click the test icon to verify.'); resetPiholeForm(); reloadPiholes(); }
    else phStatus('conn-bad','<i class="fas fa-times-circle"></i> '+(r.err||'Save failed'));
}
async function testPihole(id,btn){
    if(btn){ btn.innerHTML='<i class="fas fa-circle-notch fa-spin"></i>'; }
    phStatus('conn-unk','<i class="fas fa-circle-notch fa-spin"></i> Authenticating…');
    const r=await fetch('net_mon_config.php?api=pihole_test&id='+id).then(r=>r.json()).catch(()=>({ok:false}));
    if(btn){ btn.innerHTML='<i class="fas fa-satellite-dish"></i>'; }
    phStatus(r.ok?'conn-ok':'conn-bad', r.ok?('<i class="fas fa-check-circle"></i> Connected'+(r.version?(' — Pi-hole '+r.version):'')):('<i class="fas fa-times-circle"></i> '+(r.err||'Failed')));
}
async function deletePihole(id,name){
    if(!confirm('Delete Pi-hole "'+name+'"?')) return;
    const fd=new FormData(); fd.append('id',id);
    await fetch('net_mon_config.php?api=pihole_server_delete',{method:'POST',body:fd});
    reloadPiholes(); resetPiholeForm();
}
async function saveNetflow(){
    const fd=new FormData(document.getElementById('nf-form'));
    if(document.getElementById('nf-enabled').checked) fd.set('netflow_enabled','1'); else fd.set('netflow_enabled','0');
    const r=await fetch('net_mon_config.php?api=netflow_save',{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false}));
    const box=document.getElementById('nf-status'), txt=document.getElementById('nf-status-text');
    box.className=r.ok?'conn-status conn-ok':'conn-status conn-bad';
    txt.innerHTML=r.ok?('<i class="fas fa-check-circle"></i> Saved.'+(r.note?' '+r.note:'')):('<i class="fas fa-times-circle"></i> '+(r.err||'Save failed'));
}
async function checkNetflow(){
    const box=document.getElementById('nf-status'), txt=document.getElementById('nf-status-text');
    box.className='conn-status conn-unk'; txt.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> Checking…';
    const r=await fetch('net_mon_config.php?api=netflow_status').then(r=>r.json()).catch(()=>({ok:false}));
    if(!r.ok){ box.className='conn-status conn-bad'; txt.textContent='Status check failed'; return; }
    const s=r.status;
    if(s.alive){ box.className='conn-status conn-ok'; txt.innerHTML='<i class="fas fa-circle-check"></i> Collector live — '+(s.flows||0).toLocaleString()+' flows, '+(s.packets||0).toLocaleString()+' packets, '+(s.exporters||0)+' exporter(s)'+(s.dropped>0?', '+s.dropped+' dropped':''); }
    else if(s.last_flush_ts){ box.className='conn-status conn-bad'; txt.innerHTML='<i class="fas fa-triangle-exclamation"></i> Collector stale ('+s.age_sec+'s ago) — is the daemon running &amp; the UDP port published?'; }
    else { box.className='conn-status conn-unk'; txt.innerHTML='<i class="fas fa-circle-question"></i> No flow data yet — enable, point routers here, and publish the UDP port.'; }
}
async function saveSmtp(){
    const fd=new FormData();
    fd.append('smtp_enabled', document.getElementById('smtp-enabled').checked?'1':'0');
    fd.append('smtp_host', document.getElementById('smtp-host').value.trim());
    fd.append('smtp_port', document.getElementById('smtp-port').value.trim());
    fd.append('smtp_secure', document.getElementById('smtp-secure').value);
    fd.append('smtp_user', document.getElementById('smtp-user').value.trim());
    fd.append('smtp_pass', document.getElementById('smtp-pass').value);   // blank = keep
    fd.append('smtp_from', document.getElementById('smtp-from').value.trim());
    fd.append('smtp_from_name', document.getElementById('smtp-from-name').value.trim());
    const box=document.getElementById('smtp-status'), txt=document.getElementById('smtp-status-text');
    const r=await fetch('net_mon_config.php?api=smtp_save',{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false}));
    box.style.display='flex'; box.className=r.ok?'conn-status conn-ok':'conn-status conn-bad';
    txt.innerHTML=r.ok?'<i class="fas fa-check-circle"></i> Saved — click "Send test" to verify.':'<i class="fas fa-times-circle"></i> '+(r.err||'Save failed');
    document.getElementById('smtp-pass').value='';
}
async function testSmtp(){
    const to=document.getElementById('smtp-test-to').value.trim();
    const box=document.getElementById('smtp-status'), txt=document.getElementById('smtp-status-text');
    box.style.display='flex'; box.className='conn-status conn-unk'; txt.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> Sending test email…';
    const r=await fetch('net_mon_config.php?api=smtp_test'+(to?('&to='+encodeURIComponent(to)):'')).then(r=>r.json()).catch(()=>({ok:false}));
    box.className=r.ok?'conn-status conn-ok':'conn-status conn-bad';
    txt.innerHTML=r.ok?('<i class="fas fa-check-circle"></i> Test email sent to '+r.to+' — check the inbox.'):('<i class="fas fa-times-circle"></i> '+(r.err||'Failed'));
}
async function syslogStatus(){
    const box=document.getElementById('sy-status'), txt=document.getElementById('sy-status-text');
    box.className='conn-status conn-unk'; txt.textContent='Checking…';
    const r=await fetch('net_mon_config.php?api=syslog_status').then(r=>r.json()).catch(()=>({ok:false}));
    if(!r.ok){ box.className='conn-status conn-bad'; txt.textContent='Status check failed'; return; }
    if(!r.table){ box.className='conn-status conn-bad'; txt.innerHTML='<i class="fas fa-circle-xmark"></i> No data yet — start the daemon &amp; point devices here.'; return; }
    const live=(+r.last5m)>0;
    box.className=live?'conn-status conn-ok':'conn-status conn-unk';
    txt.innerHTML=`<i class="fas fa-${live?'check-circle':'circle-question'}"></i> ${live?'Receiving':'Idle'} — ${r.last5m||0} in last 5m · ${r.total||0} total · ${r.sources||0} source(s)${r.last_at?(' · last '+_esc(r.last_at)):''}`;
}
async function saveSyslog(){
    const fd=new FormData();
    fd.append('log_source', document.getElementById('sy-source').value);
    fd.append('syslog_port', document.getElementById('sy-port').value.trim());
    fd.append('syslog_retention_days', document.getElementById('sy-ret').value.trim());
    fd.append('syslog_tcp_enabled', document.getElementById('sy-tcp').checked?'1':'0');
    const r=await fetch('net_mon_config.php?api=syslog_save',{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false}));
    const box=document.getElementById('sy-status'), txt=document.getElementById('sy-status-text');
    box.className=r.ok?'conn-status conn-ok':'conn-status conn-bad';
    txt.innerHTML=r.ok?('<i class="fas fa-check-circle"></i> Saved. '+_esc(r.note||'')):'<i class="fas fa-times-circle"></i> Save failed';
}
async function saveN8n(){
    const body={ base_url:document.getElementById('n8n-base').value.trim(), api_key:document.getElementById('n8n-key').value.trim(), portal_base:document.getElementById('n8n-portal').value.trim() };
    const r=await fetch('net_mon_config.php?api=n8n_save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json()).catch(()=>({ok:false}));
    const m=document.getElementById('n8n-msg'); m.textContent=r.ok?'Saved.':'Save failed'; m.style.color=r.ok?'#2ecc71':'#e74c3c'; setTimeout(()=>m.textContent='',3000);
}
async function saveAiGateway(){
    const body={ conn_key:document.getElementById('ai-conn').value.trim(), vkey:document.getElementById('ai-vkey').value.trim(), public_base:document.getElementById('ai-pubbase').value.trim() };
    const r=await fetch('net_mon_config.php?api=ai_gateway_save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json()).catch(()=>({ok:false}));
    const m=document.getElementById('ai-gw-msg'); m.textContent=r.ok?'Saved.':'Save failed'; m.style.color=r.ok?'#2ecc71':'#e74c3c'; setTimeout(()=>m.textContent='',3000);
}
async function syncFlows(){
    const m=document.getElementById('ai-gw-msg');
    m.style.color='#b07cd6'; m.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> Syncing flows from the Portal…';
    let r; try{ r=await fetch('net_mon_config.php?api=flows_sync',{cache:'no-store'}).then(r=>r.json()); }catch(e){ r={ok:false,error:'request failed'}; }
    if(r && r.ok){
        m.style.color='#2ecc71';
        m.innerHTML='<i class="fas fa-check"></i> Synced '+(r.applied||0)+' flow(s)'+(r.disabled?(' · '+r.disabled+' revoked'):'')+(r.plan?(' · plan '+esc(r.plan)):'')+'.';
        if(typeof loadWebhooks==='function') loadWebhooks(); else setTimeout(()=>location.reload(),1200);
    } else {
        m.style.color='#e0a559'; m.innerHTML='<i class="fas fa-triangle-exclamation"></i> '+esc((r&&r.error)||'sync failed');
    }
    setTimeout(()=>{ if(m.textContent.indexOf('Syncing')<0) return; },6000);
}
let WG_ON=false;
function wgRender(st){
    WG_ON = (st && st.status==='on');
    const sEl=document.getElementById('wg-state'), bEl=document.getElementById('wg-toggle-btn'), lEl=document.getElementById('wg-toggle-lbl');
    if(WG_ON){ sEl.innerHTML='<i class="fas fa-circle" style="font-size:8px;color:#2ecc71;"></i> Connected'+(st.ip?(' — tunnel IP <b>'+esc(st.ip)+'</b>'):''); bEl.className='btn btn-sm btn-danger'; lEl.textContent='Disable connection'; }
    else { sEl.innerHTML='<i class="fas fa-circle" style="font-size:8px;color:#666;"></i> Off'+(st&&st.last_err?(' — <span style="color:#e08a8a;">'+esc(st.last_err)+'</span>'):''); bEl.className='btn btn-sm btn-success'; lEl.textContent='Enable connection'; }
    if(st && st.writable===false){ document.getElementById('wg-msg').innerHTML='<span style="color:#e0a559;">⚠ The <code>wg/</code> folder isn\'t writable by www-data — enabling will fail until it is (the installer/entrypoint sets this up).</span>'; }
}
async function wgStatus(){ const r=await fetch('net_mon_config.php?api=wg_status',{cache:'no-store'}).then(r=>r.json()).catch(()=>null); if(r&&r.ok) wgRender(r.state); }
async function wgToggle(){
    const m=document.getElementById('wg-msg'), b=document.getElementById('wg-toggle-btn'); b.disabled=true;
    const enabling = !WG_ON;
    m.style.color='#888'; m.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> '+(enabling?'Requesting tunnel from the Portal…':'Disabling…');
    const api=enabling?'wg_enroll':'wg_disable', target=enabling?'on':'off';
    // Fire the action but DON'T block the UI on its POST response (some setups stall the POST
    // response even though the server executes it). Instead poll the state via GET (reliable)
    // and reflect the real, server-side outcome.
    // Use GET (no body) — the POST path stalls in some browsers via keep-alive + an
    // unconsumed request body; wg_status (GET) is proven reliable, so route the action the same way.
    let acted=null;
    fetch('net_mon_config.php?api='+api,{cache:'no-store'})
        .then(r=>r.json()).then(j=>{acted=j;}).catch(()=>{acted={ok:false};});
    let tries=0;
    const poll=setInterval(async()=>{
        tries++;
        const r=await fetch('net_mon_config.php?api=wg_status',{cache:'no-store'}).then(r=>r.json()).catch(()=>null);
        if(r&&r.ok){
            wgRender(r.state);
            if(r.state.status===target){
                clearInterval(poll); b.disabled=false;
                if(target==='on'){ m.style.color='#2ecc71'; m.innerHTML='<i class="fas fa-check"></i> Connected — tunnel IP <b>'+esc(r.state.ip||'')+'</b>. Flows can now reach this NEURU.'; }
                else { m.style.color='#2ecc71'; m.innerHTML='Disabled.'; }
                return;
            }
            if(r.state.last_err && acted && acted.ok===false){
                clearInterval(poll); b.disabled=false; m.style.color='#e74c3c';
                m.innerHTML='<i class="fas fa-triangle-exclamation"></i> '+esc(r.state.last_err); return;
            }
        }
        if(tries>=25){ clearInterval(poll); b.disabled=false; m.style.color='#e74c3c';
            m.innerHTML='<i class="fas fa-triangle-exclamation"></i> '+esc((acted&&acted.error)||'Timed out — verify the Portal /v1/wg endpoint.'); }
    }, 1200);
}
async function genToken(){
    if(document.getElementById('n8n-token').value && !confirm('Rotate the inbound token? Existing n8n credentials using the old token will stop working.')) return;
    const r=await fetch('net_mon_config.php?api=n8n_gen_token',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>r.json()).catch(()=>({ok:false}));
    if(r.ok){ document.getElementById('n8n-token').value=r.token; const m=document.getElementById('n8n-msg'); m.textContent='Token generated — copy it into n8n.'; m.style.color='#2ecc71'; setTimeout(()=>m.textContent='',5000); }
}
function copyToken(){ const el=document.getElementById('n8n-token'); if(!el.value) return; navigator.clipboard?.writeText(el.value); const m=document.getElementById('n8n-msg'); m.textContent='Copied.'; m.style.color='#2ecc71'; setTimeout(()=>m.textContent='',2000); }

function webhookForm(w){ w=w||{}; document.getElementById('wh-form').style.display='block';
    document.getElementById('wh-id').value=w.id||0; document.getElementById('wh-name').value=w.name||'';
    document.getElementById('wh-slug').value=w.slug||''; document.getElementById('wh-url').value=w.url||'';
    document.getElementById('wh-method').value=w.method||'POST'; document.getElementById('wh-desc').value=w.description||'';
    document.getElementById('wh-enabled').checked=w.enabled===undefined?true:(w.enabled==1); }
async function saveWebhook(){
    const body={ id:+document.getElementById('wh-id').value, name:document.getElementById('wh-name').value.trim(),
        slug:document.getElementById('wh-slug').value.trim(), url:document.getElementById('wh-url').value.trim(),
        method:document.getElementById('wh-method').value, description:document.getElementById('wh-desc').value.trim(),
        enabled:document.getElementById('wh-enabled').checked };
    if(!body.name||!body.slug||!body.url){ alert('Name, slug and URL are required.'); return; }
    const r=await fetch('net_mon_config.php?api=webhook_save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json()).catch(()=>({ok:false}));
    if(r.ok){ document.getElementById('wh-form').style.display='none'; loadWebhooks(); } else alert(r.err||'Save failed');
}
async function loadWebhooks(){
    const tb=document.getElementById('wh-tbody'); if(!tb) return;
    try{ const r=await fetch('net_mon_config.php?api=webhook_list').then(r=>r.json()); const W=r.webhooks||[];
        if(!W.length){ tb.innerHTML='<tr><td colspan="4" style="color:#777;padding:12px;text-align:center;">No webhooks yet — add one per AI solution.</td></tr>'; return; }
        tb.innerHTML=W.map(w=>`<tr style="border-top:1px solid #1d222b;">
            <td style="padding:6px;"><b>${_esc(w.name)}</b><br><code style="color:#b07cd6;font-size:11px;">${_esc(w.slug)}</code></td>
            <td style="padding:6px;color:#888;font-size:11px;word-break:break-all;">${_esc(w.method)} ${_esc(w.url)}${w.description?`<br><span style="color:#666;">${_esc(w.description)}</span>`:''}</td>
            <td style="padding:6px;text-align:center;">${w.enabled==1?'<span style="color:#2ecc71;">●</span>':'<span style="color:#666;">○</span>'}</td>
            <td style="padding:6px;text-align:right;white-space:nowrap;">
                <button class="btn btn-sm" title="Test fire" onclick='testWebhook(${JSON.stringify(w.slug)})'><i class="fas fa-bolt"></i></button>
                <button class="btn btn-sm" onclick='webhookForm(${JSON.stringify(w)})'><i class="fas fa-pen"></i></button>
                <button class="btn btn-sm" style="border-color:#e74c3c;color:#e74c3c;" onclick="deleteWebhook(${w.id})"><i class="fas fa-trash"></i></button>
            </td></tr>`).join('');
    }catch(e){ tb.innerHTML='<tr><td colspan="4" style="color:#e74c3c;padding:12px;text-align:center;">Error loading.</td></tr>'; }
}
async function deleteWebhook(id){ if(!confirm('Delete this webhook?')) return;
    await fetch('net_mon_config.php?api=webhook_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); loadWebhooks(); }
async function testWebhook(slug){
    const r=await fetch('net_mon_config.php?api=webhook_test&slug='+encodeURIComponent(slug)).then(r=>r.json()).catch(()=>({ok:false}));
    let body=''; if(r.resp!=null) body='\n\nn8n said:\n'+(typeof r.resp==='string'?r.resp:JSON.stringify(r.resp,null,2));
    let head;
    if(r.ok)          head='✓ Webhook responded (HTTP '+r.code+').';
    else if(r.async)  head='⚠ Reachable — the flow accepted the request but replies asynchronously via callback (this is NORMAL for exec/suggest flows like rc-exec, rc-suggest, self-heal-apply — they run the work and post results back, so a synchronous test times out on purpose).';
    else              head='✗ Test failed: '+(r.err||'unknown')+(r.code?(' [HTTP '+r.code+']'):'');
    alert(head+body); }
// ── SSH credentials (self-heal) ───────────────────────────────────────────────
let _sshCreds=[];
async function loadSsh(){
    const tb=document.getElementById('ssh-tbody'); if(!tb) return;
    try{ const r=await fetch('net_mon_config.php?api=ssh_cred_list').then(r=>r.json()); _sshCreds=r.creds||[];
        tb.innerHTML = _sshCreds.length ? _sshCreds.map(c=>`<tr style="border-top:1px solid #1d222b;">
            <td style="padding:6px;"><b>${_esc(c.name)}</b></td>
            <td style="padding:6px;color:#aaa;">${_esc(c.username)} · ${_esc(c.auth_type)}</td>
            <td style="padding:6px;text-align:center;color:#888;">${c.port}</td>
            <td style="padding:6px;text-align:center;">${c.has_secret==1?'<span style="color:#2ecc71;">●</span>':'<span style="color:#e67e22;">none</span>'}</td>
            <td style="padding:6px;text-align:center;">${c.is_default==1?'<i class="fas fa-star" style="color:#f1c40f;"></i>':''}</td>
            <td style="padding:6px;text-align:right;white-space:nowrap;">
                <button class="btn btn-sm" onclick='sshForm(${JSON.stringify(c)})'><i class="fas fa-pen"></i></button>
                <button class="btn btn-sm" style="border-color:#e74c3c;color:#e74c3c;" onclick="sshDel(${c.id})"><i class="fas fa-trash"></i></button>
            </td></tr>`).join('') : '<tr><td colspan="6" style="color:#777;padding:12px;text-align:center;">No credentials yet — add one (mark it Default).</td></tr>';
    }catch(e){ tb.innerHTML='<tr><td colspan="6" style="color:#e74c3c;padding:12px;text-align:center;">Error.</td></tr>'; }
    loadSshMap();
    loadHostMap();
}
function sshForm(c){ c=c||{}; document.getElementById('ssh-form').style.display='block';
    document.getElementById('ssh-id').value=c.id||0; document.getElementById('ssh-name').value=c.name||'';
    document.getElementById('ssh-user').value=c.username||''; document.getElementById('ssh-auth').value=c.auth_type||'password';
    document.getElementById('ssh-port').value=c.port||22; document.getElementById('ssh-default').checked=(c.is_default==1);
    document.getElementById('ssh-secret').value=''; document.getElementById('ssh-sec-lbl').textContent=(c.auth_type==='key')?'Private key':'Password'; }
async function sshSave(){
    const body={ id:+document.getElementById('ssh-id').value, name:document.getElementById('ssh-name').value.trim(),
        username:document.getElementById('ssh-user').value.trim(), auth_type:document.getElementById('ssh-auth').value,
        port:+document.getElementById('ssh-port').value||22, is_default:document.getElementById('ssh-default').checked,
        secret:document.getElementById('ssh-secret').value };
    if(!body.name||!body.username){ alert('Name and username are required.'); return; }
    const r=await fetch('net_mon_config.php?api=ssh_cred_save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json()).catch(()=>({ok:false}));
    if(r.ok){ document.getElementById('ssh-form').style.display='none'; loadSsh(); } else alert(r.err||'Save failed');
}
async function sshDel(id){ if(!confirm('Delete this credential? Devices using it fall back to Default.'))return;
    await fetch('net_mon_config.php?api=ssh_cred_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); loadSsh(); }
async function loadSshMap(){
    const tb=document.getElementById('ssh-map-tbody'); if(!tb) return;
    try{ const r=await fetch('net_mon_config.php?api=node_cred_map').then(r=>r.json()); const N=r.nodes||[];
        const opts=cur=>`<option value="0"${!cur?' selected':''}>— Default —</option>`+_sshCreds.map(c=>`<option value="${c.id}"${cur==c.id?' selected':''}>${_esc(c.name)}</option>`).join('');
        tb.innerHTML = N.length ? N.map(n=>`<tr style="border-top:1px solid #1d222b;">
            <td style="padding:6px;"><b>${_esc(n.display_name)}</b></td>
            <td style="padding:6px;color:#888;font-family:monospace;">${_esc(n.ip_address)}</td>
            <td style="padding:6px;"><select class="form-select" style="font-size:12px;padding:4px 8px;" onchange="sshAssign(${n.id},this.value)">${opts(n.ssh_cred_id)}</select></td>
        </tr>`).join('') : '<tr><td colspan="3" style="color:#777;padding:12px;text-align:center;">No devices.</td></tr>';
    }catch(e){ tb.innerHTML='<tr><td colspan="3" style="color:#e74c3c;padding:12px;text-align:center;">Error.</td></tr>'; }
}
async function sshAssign(node_id,cred_id){
    await fetch('net_mon_config.php?api=ssh_cred_assign',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id,cred_id:+cred_id})});
}
async function loadHostMap(){
    const tb=document.getElementById('ssh-host-tbody'); if(!tb) return;
    try{ const r=await fetch('net_mon_config.php?api=host_cred_map').then(r=>r.json()); const H=r.hosts||[];
        const opts=cur=>`<option value="0"${!cur?' selected':''}>— Default —</option>`+_sshCreds.map(c=>`<option value="${c.id}"${cur==c.id?' selected':''}>${_esc(c.name)}</option>`).join('');
        if(!r.portainer){ tb.innerHTML='<tr><td colspan="3" style="color:#777;padding:12px;text-align:center;">Connect Portainer in <a href="net_mon_config.php?tab=containers" style="color:var(--accent)">Config → Containers</a> to list Docker hosts.</td></tr>'; return; }
        tb.innerHTML = H.length ? H.map(h=>`<tr style="border-top:1px solid #1d222b;">
            <td style="padding:6px;"><b>${_esc(h.name||h.host)}</b></td>
            <td style="padding:6px;color:#888;font-family:monospace;">${_esc(h.host)}</td>
            <td style="padding:6px;"><select class="form-select" style="font-size:12px;padding:4px 8px;" onchange="hostAssign('${_esc(h.host)}',this.value)">${opts(h.cred_id)}</select></td>
        </tr>`).join('') : '<tr><td colspan="3" style="color:#777;padding:12px;text-align:center;">No Docker hosts found.</td></tr>';
    }catch(e){ tb.innerHTML='<tr><td colspan="3" style="color:#e74c3c;padding:12px;text-align:center;">Error.</td></tr>'; }
}
async function hostAssign(host,cred_id){
    await fetch('net_mon_config.php?api=host_cred_assign',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,cred_id:+cred_id})});
}

if(new URLSearchParams(location.search).get('tab')==='integrations'){ loadWebhooks(); }
if(new URLSearchParams(location.search).get('tab')==='credentials'){ loadSsh(); }
async function saveRc(){
    const b={ rc_suggest_url:document.getElementById('rc-suggest').value.trim(), rc_execute_url:document.getElementById('rc-exec').value.trim() };
    const m=document.getElementById('rc-msg'); m.style.color='#888'; m.textContent='Saving…';
    const r=await fetch('router_commander.php?api=save_settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json()).catch(()=>({ok:false}));
    m.style.color=r.ok?'#2ecc71':'#e74c3c'; m.textContent=r.ok?'Saved ✓':(r.error||'Failed');
}

function copyCtrKey(){ const el=document.getElementById('ctr-key'); if(!el.value){ alert('Generate the token in Integrations & AI first.'); return; }
    navigator.clipboard?.writeText(el.value); const m=document.getElementById('ctr-key-msg'); if(m){ m.textContent='Copied.'; setTimeout(()=>m.textContent='',2000); } }

// ── Portainer connection test ─────────────────────────────────────────────────
async function testPortainer(){
    const box=document.getElementById('ptn-status'), txt=document.getElementById('ptn-status-text');
    box.className='conn-status conn-unk'; txt.textContent='Testing…';
    const url=encodeURIComponent(document.getElementById('ptn-url').value.trim());
    const key=encodeURIComponent(document.getElementById('ptn-key').value.trim());
    const verify=document.getElementById('ptn-verify').checked?'1':'0';
    try{ const r=await fetch(`net_mon_config.php?api=portainer_test&url=${url}&key=${key}&verify=${verify}`).then(r=>r.json());
        if(r.ok){ box.className='conn-status conn-ok'; txt.innerHTML=`<i class="fas fa-check-circle"></i> Connected — Portainer ${_esc(r.version)} · ${r.env_count} environment(s)`; }
        else { box.className='conn-status conn-bad'; txt.innerHTML=`<i class="fas fa-times-circle"></i> ${_esc(r.err||'Failed')}`; }
    }catch(e){ box.className='conn-status conn-bad'; txt.textContent='Request failed'; }
}

// ── Enable toggle label ───────────────────────────────────────────────────────
document.getElementById('lnms-enabled-chk')?.addEventListener('change', function(){
    const lbl = document.getElementById('enabled-lbl');
    lbl.textContent = this.checked ? 'Enabled — API calls active' : 'Disabled — no API calls made';
    lbl.style.color = this.checked ? 'var(--up)' : 'var(--down)';
});

// ── Test connection ───────────────────────────────────────────────────────────
async function testConnection() {
    const el  = document.getElementById('conn-status');
    const txt = document.getElementById('conn-status-text');
    el.className = 'conn-status conn-unk';
    txt.innerHTML = '<span class="spinner"></span> Testing…';
    try {
        const r = await fetch('net_mon_config.php?api=test').then(r=>r.json());
        if (r.ok) {
            el.className = 'conn-status conn-ok';
            txt.innerHTML = `<i class="fas fa-check-circle"></i> Connected — LibreNMS v${r.ver} · DB schema ${r.db}`;
        } else {
            el.className = 'conn-status conn-off';
            txt.innerHTML = `<i class="fas fa-times-circle"></i> ${r.err}`;
        }
    } catch(e) {
        el.className = 'conn-status conn-off';
        txt.innerHTML = '<i class="fas fa-times-circle"></i> Network error — cannot reach server';
    }
}

// ── Device browser ─────────────────────────────────────────────────────────────
let _allDevices = [];

async function browseDevices() {
    const btn = document.getElementById('browse-btn');
    const st  = document.getElementById('browse-status');
    btn.innerHTML = '<span class="spinner"></span> Loading…';
    btn.disabled  = true;
    st.style.display = 'block';
    st.textContent   = 'Fetching device list from LibreNMS…';
    try {
        const r = await fetch('net_mon_config.php?api=devices').then(r=>r.json());
        _allDevices = r.devices || [];
        if (!_allDevices.length) {
            st.textContent = r.err || 'No devices found in LibreNMS.';
        } else {
            st.textContent = `Found ${_allDevices.length} device(s).`;
            document.getElementById('device-browser').style.display = 'block';
            renderDevices(_allDevices);
        }
    } catch(e) {
        st.textContent = 'Error fetching devices — is LibreNMS reachable?';
    }
    btn.innerHTML = '<i class="fas fa-satellite-dish"></i> Browse LibreNMS Devices';
    btn.disabled  = false;
}

function renderDevices(devs) {
    const tbody = document.getElementById('dev-tbody');
    if (!tbody) return;
    tbody.innerHTML = devs.map(d => {
        const host = d.hostname||d.sysName||'?';
        const ip   = d.ip||d.hostname||'?';
        const os   = d.os||'generic';
        return `<tr>
            <td><strong>${escHtml(host)}</strong></td>
            <td style="font-family:monospace;font-size:11px;">${escHtml(ip)}</td>
            <td><span class="os-badge">${escHtml(os)}</span></td>
            <td><button class="btn btn-success btn-sm" onclick="pickDevice('${escHtml(host)}','${escHtml(ip)}','${escHtml(os)}')"><i class="fas fa-arrow-up"></i> Use</button></td>
        </tr>`;
    }).join('');
}

function filterDevices() {
    const q = document.getElementById('dev-search').value.toLowerCase();
    const filtered = q ? _allDevices.filter(d =>
        (d.hostname||'').toLowerCase().includes(q) ||
        (d.ip||'').toLowerCase().includes(q) ||
        (d.os||'').toLowerCase().includes(q) ||
        (d.location||'').toLowerCase().includes(q)
    ) : _allDevices;
    renderDevices(filtered);
}

function pickDevice(host, ip, os) {
    // Populate the direct Add Device form from LibreNMS browser selection
    const dnEl = document.getElementById('anf-display');
    const ipEl = document.getElementById('anf-ip');
    const icEl = document.getElementById('anf-icon');
    if (dnEl && !dnEl.value) dnEl.value = host;
    if (ipEl) ipEl.value = ip;
    // Map LibreNMS OS to icon value
    const osMap = {routeros:'routeros', linux:'linux', windows:'windows', cisco:'cisco'};
    if (icEl) icEl.value = osMap[os] || 'generic';
    // Scroll to Add Device form
    document.getElementById('add-node-form')?.scrollIntoView({behavior:'smooth',block:'start'});
}

// ── Interface management (DB-based, direct SNMP) ─────────────────────────────
async function loadNodeIfacesDirect() {
    const sel = document.getElementById('iface-node-sel');
    if (!sel) return;
    const nid = parseInt(sel.value, 10);
    document.getElementById('iface-node-id').value = nid;
    const st  = document.getElementById('iface-status');
    st.innerHTML = '<span class="spinner"></span>';
    document.getElementById('iface-content').innerHTML =
        '<div style="color:#888;font-size:13px;padding:20px 0;text-align:center;"><span class="spinner"></span>&nbsp; Loading…</div>';

    const r = await fetch(`net_mon_config.php?api=get_node_ifaces&node_id=${nid}`).then(r=>r.json()).catch(()=>({ifaces:[]}));
    const ifaces = r.ifaces || [];
    st.textContent = `${ifaces.length} interface(s)`;

    if (!ifaces.length) {
        document.getElementById('iface-content').innerHTML = `
            <div style="text-align:center;padding:30px;color:#555;">
                <i class="fas fa-ethernet" style="font-size:28px;margin-bottom:10px;display:block;"></i>
                No interfaces yet. Click <strong>Discover via SNMP</strong> to auto-detect.
            </div>`;
        return;
    }

    const rows = ifaces.map(i => {
        const monitored = parseInt(i.show_graph) === 1;
        const idxBadge  = i.if_index ? `<span style="font-size:9px;color:#555;font-family:monospace;">idx:${i.if_index}</span>` : '';
        return `<tr id="ifrow-${i.id}">
            <td style="width:60px;text-align:center;">
                <label class="toggle-switch" style="transform:scale(.85);margin:0;">
                    <input type="checkbox" ${monitored?'checked':''} onchange="toggleIfaceMonitor(${i.id},this.checked)">
                    <span class="toggle-slider"></span>
                </label>
            </td>
            <td>
                <span style="font-family:monospace;font-size:12px;color:#4da3ff;">${escHtml(i.if_name||'?')}</span>
                ${idxBadge}
            </td>
            <td>
                <input class="form-input" type="text" id="dn-${i.id}"
                       value="${escHtml(i.display_name||i.if_name||'')}"
                       style="padding:4px 8px;font-size:11px;"
                       placeholder="Display name"
                       onblur="saveIfaceDisplayName(${i.id})">
            </td>
            <td>
                <input class="form-input" type="text" id="ip-${i.id}"
                       value="${escHtml(i.if_ip_address||'')}"
                       style="padding:4px 8px;font-size:11px;font-family:monospace;"
                       placeholder="e.g. 192.168.20.1"
                       title="Interface IP — used by the network map for multi-subnet routers"
                       onblur="saveIfaceIp(${i.id})">
            </td>
            <td style="text-align:right;">
                <button class="btn btn-danger btn-sm" style="padding:3px 8px;" onclick="delIface(${i.id})">
                    <i class="fas fa-trash"></i>
                </button>
            </td>
        </tr>`;
    });

    document.getElementById('iface-content').innerHTML = `
        <table class="iface-table" style="width:100%;">
            <thead><tr>
                <th style="width:60px;text-align:center;">Monitor</th>
                <th>Interface</th>
                <th>Display Name</th>
                <th>Interface IP</th>
                <th style="width:60px;"></th>
            </tr></thead>
            <tbody>${rows.join('')}</tbody>
        </table>
        <div style="margin-top:8px;font-size:11px;color:#555;">
            <i class="fas fa-info-circle"></i> Toggle to include in graphs. Interface IP helps the map link routers to multiple subnets.
        </div>`;
}

async function toggleIfaceMonitor(id, on) {
    await fetch('net_mon_config.php?api=update_iface', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({id, show_graph: on ? 1 : 0})
    }).then(r=>r.json()).catch(()=>{});
}

async function saveIfaceDisplayName(id) {
    const val = document.getElementById('dn-'+id)?.value.trim();
    if (!val) return;
    await fetch('net_mon_config.php?api=update_iface', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({id, display_name: val})
    }).then(r=>r.json()).catch(()=>{});
}

async function saveIfaceIp(id) {
    const val = (document.getElementById('ip-'+id)?.value || '').trim();
    await fetch('net_mon_config.php?api=update_iface', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({id, if_ip_address: val})
    }).then(r=>r.json()).catch(()=>{});
}

async function delIface(id) {
    if (!confirm('Remove this interface?')) return;
    await fetch('net_mon_config.php?api=del_iface', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({id})
    }).then(r=>r.json()).catch(()=>{});
    loadNodeIfacesDirect();
}

async function discoverIfaces() {
    const nid = parseInt(document.getElementById('iface-node-id')?.value || document.getElementById('iface-node-sel')?.value, 10);
    if (!nid) return;
    const st = document.getElementById('iface-status');
    st.innerHTML = '<span class="spinner"></span> Discovering…';
    const r = await fetch(`net_mon_config.php?api=discover_ifaces&node_id=${nid}`, {credentials:'same-origin'})
        .then(r=>r.json()).catch(()=>({ok:false,err:'Network error'}));
    if (r.ok) {
        st.innerHTML = `<span style="color:var(--up)"><i class="fas fa-check"></i> Found ${r.found}, added ${r.added}, updated ${r.updated}</span>`;
        loadNodeIfacesDirect();
        setTimeout(()=>{ st.innerHTML=''; }, 5000);
    } else {
        st.innerHTML = `<span style="color:var(--down)"><i class="fas fa-times-circle"></i> ${escHtml(r.err||'Discovery failed')}</span>`;
    }
}

function setIfaceNode(nid) {
    const sel = document.getElementById('iface-node-sel');
    if (!sel) return;
    sel.value = nid;
    document.getElementById('iface-node-id').value = nid;
    loadNodeIfacesDirect();
}

// Load the interfaces panel once on startup (the DOM above is already parsed, so a
// direct call is reliable even if DOMContentLoaded already fired). The panel stays
// hidden until its tab is shown — this just guarantees it's never stuck on "Loading…".
<?php if (!empty($nodes)): ?>
try { loadNodeIfacesDirect(); } catch(e){}
<?php endif ?>

// ── SNMP OIDs tab ─────────────────────────────────────────────────────────────
let _activeTplId   = null;
let _activeTplBuiltin = false;

// Filter the (now scrollable) template library by name / vendor.
function filterTemplates() {
    const q = (document.getElementById('tplFilter').value || '').trim().toLowerCase();
    let shown = 0;
    document.querySelectorAll('#tplList .tpl-card').forEach(c => {
        const hit = !q || (c.dataset.search || '').indexOf(q) !== -1;
        c.style.display = hit ? '' : 'none';
        if (hit) shown++;
    });
    const empty = document.getElementById('tplEmpty');
    if (empty) empty.style.display = shown ? 'none' : 'block';
}
// Collapse/expand the "create custom template" form.
function toggleCreateTpl() {
    const f = document.getElementById('tplCreateForm');
    const ch = document.getElementById('tplCreateChevron');
    const open = f.style.display === 'none';
    f.style.display = open ? 'block' : 'none';
    if (ch) ch.style.transform = open ? 'rotate(180deg)' : '';
}

function oidTypeBadge(t) {
    const cls = { cpu:'oid-type-cpu', memory:'oid-type-memory', disk:'oid-type-disk',
                  temperature:'oid-type-temperature', custom:'oid-type-custom' };
    return `<span class="oid-badge ${cls[t]||'oid-type-custom'}">${escHtml(t||'custom')}</span>`;
}

function renderOidRows(oids, showDelete, onDelete) {
    if (!oids.length) return '<div style="color:#555;font-size:12px;padding:10px 0;">No OIDs defined.</div>';
    return oids.map(o => `
        <div class="oid-row">
            <div class="oid-name">${escHtml(o.metric_name)}</div>
            ${oidTypeBadge(o.metric_type)}
            <div class="oid-string">${escHtml(o.oid)}${o.oid_total?' <span style="color:#888;">/ '+escHtml(o.oid_total)+'</span>':''}</div>
            <span style="font-size:10px;color:#666;">${escHtml(o.unit||'%')}${o.scale!=1?' ×'+parseFloat(o.scale).toFixed(3):''}${o.walk?' walk':''}</span>
            ${showDelete ? `<button class="btn btn-danger btn-sm" style="padding:2px 8px;font-size:10px;" onclick="${onDelete}(${o.id})"><i class="fas fa-trash"></i></button>` : ''}
        </div>
    `).join('');
}

async function previewTemplate(tplId) {
    document.querySelectorAll('.tpl-card').forEach(c => c.classList.remove('active'));
    document.getElementById('tplcard-' + tplId)?.classList.add('active');
    _activeTplId = tplId;

    const tplData = <?= json_encode($oid_templates) ?>;
    const tpl = tplData.find(t => t.id == tplId);
    _activeTplBuiltin = tpl?.is_builtin == 1;

    document.getElementById('tpl-preview-title').textContent = tpl?.name || 'Template OIDs';
    document.getElementById('tpl-preview-content').innerHTML = '<span class="spinner"></span>';

    const r = await fetch(`net_mon_config.php?api=template_oids&template_id=${tplId}`).then(r=>r.json());
    const oids = r.oids || [];

    let html = renderOidRows(oids, !_activeTplBuiltin, 'deleteTplOid');

    if (tpl?.os_type === 'generic') {
        html = `<div style="padding:10px;background:rgba(46,204,113,.06);border:1px solid rgba(46,204,113,.2);border-radius:8px;margin-bottom:10px;font-size:11px;color:#2ecc71;">
            <i class="fas fa-check-circle"></i>
            <strong>Standard collection always active:</strong> CPU via hrProcessorLoad, memory+disk via hrStorageTable.
            No OIDs need to be listed here — assigning this template enables automatic health data for any SNMP device.
        </div>` + html;
    }

    document.getElementById('tpl-preview-content').innerHTML = html || '<div style="color:#555;font-size:12px;padding:10px;">No OIDs defined.</div>';

    // Show add OID form for custom templates
    const addCard = document.getElementById('tpl-add-oid-card');
    if (!_activeTplBuiltin) {
        addCard.style.display = 'block';
        document.getElementById('tpl-add-oid-form').innerHTML = buildTplAddForm(tplId);
    } else {
        addCard.style.display = 'none';
    }
}

function buildTplAddForm(tplId) {
    return `
    <div style="display:flex;flex-direction:column;gap:8px;">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
            <div>
                <label style="font-size:10px;color:#aaa;text-transform:uppercase;">Metric Name</label>
                <input class="form-input" type="text" id="tpl-mname" placeholder="My Sensor" style="font-size:12px;padding:6px 10px;margin-top:3px;">
            </div>
            <div>
                <label style="font-size:10px;color:#aaa;text-transform:uppercase;">Metric Type</label>
                <select class="form-select" id="tpl-mtype" style="font-size:12px;padding:6px 10px;margin-top:3px;">
                    <option value="cpu">CPU</option><option value="memory">Memory</option>
                    <option value="disk">Disk</option><option value="temperature">Temperature</option>
                    <option value="custom" selected>Custom</option>
                </select>
            </div>
        </div>
        <div>
            <label style="font-size:10px;color:#aaa;text-transform:uppercase;">OID</label>
            <input class="form-input" type="text" id="tpl-oid" placeholder=".1.3.6.1.4.1...." style="font-family:monospace;font-size:12px;padding:6px 10px;margin-top:3px;">
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
            <div>
                <label style="font-size:10px;color:#aaa;text-transform:uppercase;">Unit</label>
                <input class="form-input" type="text" id="tpl-unit" value="%" style="font-size:12px;padding:6px 10px;margin-top:3px;">
            </div>
            <div>
                <label style="font-size:10px;color:#aaa;text-transform:uppercase;">Scale</label>
                <input class="form-input" type="number" id="tpl-scale" value="1.0" step="0.001" style="font-size:12px;padding:6px 10px;margin-top:3px;">
            </div>
            <div>
                <label style="font-size:10px;color:#aaa;text-transform:uppercase;">Walk</label>
                <select class="form-select" id="tpl-walk" style="font-size:12px;padding:6px 10px;margin-top:3px;">
                    <option value="0">No</option><option value="1">Yes</option>
                </select>
            </div>
        </div>
        <div style="display:flex;gap:8px;margin-top:4px;">
            <button class="btn btn-success btn-sm" onclick="addTplOid(${tplId})"><i class="fas fa-plus"></i> Add to Template</button>
        </div>
        <div id="tpl-add-status" style="font-size:11px;"></div>
    </div>`;
}

async function addTplOid(tplId) {
    const data = {
        template_id:  tplId,
        node_id:      0,
        metric_name:  document.getElementById('tpl-mname')?.value.trim()  || '',
        metric_type:  document.getElementById('tpl-mtype')?.value         || 'custom',
        oid:          document.getElementById('tpl-oid')?.value.trim()    || '',
        unit:         document.getElementById('tpl-unit')?.value.trim()   || '%',
        scale:        parseFloat(document.getElementById('tpl-scale')?.value || 1),
        walk:         parseInt(document.getElementById('tpl-walk')?.value || 0),
        description:  '',
    };
    if (!data.metric_name || !data.oid) {
        document.getElementById('tpl-add-status').innerHTML = '<span style="color:#e74c3c">Metric name and OID are required.</span>';
        return;
    }
    const r = await fetch('net_mon_config.php?api=save_oid', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)
    }).then(r=>r.json());
    if (r.ok) {
        document.getElementById('tpl-add-status').innerHTML = '<span style="color:#2ecc71"><i class="fas fa-check"></i> OID added.</span>';
        previewTemplate(tplId);
    } else {
        document.getElementById('tpl-add-status').innerHTML = `<span style="color:#e74c3c">${escHtml(r.err||'Error')}</span>`;
    }
}

async function deleteTplOid(id) {
    if (!confirm('Remove this OID from the template?')) return;
    const r = await fetch('net_mon_config.php?api=del_oid', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})
    }).then(r=>r.json());
    if (r.ok && _activeTplId) previewTemplate(_activeTplId);
    else if (!r.ok) alert(r.err || 'Error');
}

async function loadNodeOids() {
    const sel = document.getElementById('oid-node-sel');
    if (!sel) return;
    const nid = parseInt(sel.value, 10);

    // Update template selector
    const tplSel = document.getElementById('node-tpl-sel');
    if (tplSel) {
        const opt = sel.options[sel.selectedIndex];
        const curTpl = opt?.dataset?.tplid || '';
        tplSel.value = curTpl;
    }

    document.getElementById('node-oid-list').innerHTML = '<div style="color:#555;font-size:12px;padding:10px;"><span class="spinner"></span> Loading…</div>';
    const r = await fetch(`net_mon_config.php?api=node_oids&node_id=${nid}`).then(r=>r.json());
    const oids = r.oids || [];

    if (tplSel) tplSel.value = r.template_id || '';

    const html = renderOidRows(oids, true, 'deleteNodeOid');
    document.getElementById('node-oid-list').innerHTML = html ||
        '<div style="color:#555;font-size:12px;padding:10px;">No custom OIDs for this node.</div>';
}

async function saveNodeTemplate() {
    const sel = document.getElementById('oid-node-sel');
    const tpl = document.getElementById('node-tpl-sel');
    if (!sel) return;
    const nid = parseInt(sel.value, 10);
    const tid = tpl.value ? parseInt(tpl.value, 10) : null;
    const r = await fetch('net_mon_config.php?api=save_node_template', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({node_id: nid, template_id: tid})
    }).then(r=>r.json());
    if (r.ok) {
        // Update the select option's data-tplid
        const opt = sel.options[sel.selectedIndex];
        if (opt) opt.dataset.tplid = tid || '';
        // Brief success flash
        tpl.style.borderColor = '#2ecc71';
        setTimeout(() => { tpl.style.borderColor = ''; }, 2000);
    } else {
        alert(r.err || 'Save failed');
    }
}

function toggleAddOidForm() {
    const f = document.getElementById('add-oid-form');
    f.style.display = f.style.display === 'none' ? 'block' : 'none';
}

async function addNodeOid() {
    const sel = document.getElementById('oid-node-sel');
    if (!sel) return;
    const nid  = parseInt(sel.value, 10);
    const data = {
        node_id:     nid,
        template_id: null,
        metric_name: document.getElementById('new-mname')?.value.trim()  || '',
        metric_type: document.getElementById('new-mtype')?.value         || 'custom',
        oid:         document.getElementById('new-oid')?.value.trim()    || '',
        oid_total:   document.getElementById('new-oid-total')?.value.trim() || '',
        unit:        document.getElementById('new-unit')?.value.trim()   || '%',
        scale:       parseFloat(document.getElementById('new-scale')?.value || 1),
        walk:        parseInt(document.getElementById('new-walk')?.value  || 0),
        description: '',
    };
    const st = document.getElementById('add-oid-status');
    if (!data.metric_name || !data.oid) {
        st.innerHTML = '<span style="color:#e74c3c">Metric name and OID are required.</span>';
        return;
    }
    const r = await fetch('net_mon_config.php?api=save_oid', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)
    }).then(r=>r.json());
    if (r.ok) {
        st.innerHTML = '<span style="color:#2ecc71"><i class="fas fa-check"></i> OID added.</span>';
        document.getElementById('add-oid-form').style.display = 'none';
        loadNodeOids();
        setTimeout(() => { st.innerHTML = ''; }, 3000);
    } else {
        st.innerHTML = `<span style="color:#e74c3c">${escHtml(r.err||'Error')}</span>`;
    }
}

async function deleteNodeOid(id) {
    if (!confirm('Remove this custom OID?')) return;
    const r = await fetch('net_mon_config.php?api=del_oid', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})
    }).then(r=>r.json());
    if (r.ok) loadNodeOids();
    else alert(r.err || 'Error');
}

// Load the per-node OID panel once on startup (same reliability fix as Interfaces).
<?php if (!empty($nodes)): ?>
try { loadNodeOids(); } catch(e){}
<?php endif ?>

// ── Discovery tab ─────────────────────────────────────────────────────────────
async function runDiscovery() {
    const btn = document.getElementById('disc-run-btn');
    const out = document.getElementById('disc-output');
    const st  = document.getElementById('disc-status');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Scanning…';
    st.innerHTML = '';
    out.style.display = 'block';
    out.textContent = 'Starting discovery… (may take 30–120s depending on subnet size)\n';

    try {
        const r = await fetch('net_mon_config.php?api=run_discovery', {credentials:'same-origin'}).then(r=>r.json());
        out.textContent = r.output || 'Done (no output).';
        if (r.ok) {
            st.innerHTML = '<span style="color:var(--up)"><i class="fas fa-check-circle"></i> Scan complete</span>';
            loadCandidates();
        } else {
            st.innerHTML = `<span style="color:var(--down)"><i class="fas fa-times-circle"></i> ${escHtml(r.err||'Error')}</span>`;
        }
    } catch(e) {
        out.textContent = 'Error: ' + e.message;
    }
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-play"></i> Run Discovery Now';
    setTimeout(() => { if(st.textContent) st.innerHTML=''; }, 8000);
}

async function loadCandidates() {
    const el = document.getElementById('candidates-content');
    if (!el) return;
    el.innerHTML = '<div style="text-align:center;padding:20px;"><span class="spinner"></span></div>';

    const r = await fetch('net_mon_config.php?api=get_candidates').then(r=>r.json()).catch(()=>({candidates:[]}));
    const cands = r.candidates || [];

    if (!cands.length) {
        el.innerHTML = `<div style="text-align:center;color:#555;padding:30px;">
            <i class="fas fa-satellite-dish" style="font-size:28px;display:block;margin-bottom:10px;opacity:.4;"></i>
            No candidates yet — run a discovery scan to find LAN devices.
        </div>`;
        return;
    }

    const pending  = cands.filter(c => c.status === 'pending');
    const imported = cands.filter(c => c.status === 'imported');
    const rejected = cands.filter(c => c.status === 'rejected');

    let html = '';
    if (pending.length) {
        html += `<div style="font-size:10px;color:var(--warn);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px;font-weight:700;">
            <i class="fas fa-clock"></i> ${pending.length} Pending
        </div>`;
        html += pending.map(candidateRow).join('');
    }
    if (imported.length) {
        html += `<div style="font-size:10px;color:var(--up);text-transform:uppercase;letter-spacing:.8px;margin:14px 0 8px;font-weight:700;">
            <i class="fas fa-check-circle"></i> ${imported.length} Imported
        </div>`;
        html += imported.map(candidateRow).join('');
    }
    if (rejected.length) {
        html += `<div style="font-size:10px;color:#555;text-transform:uppercase;letter-spacing:.8px;margin:14px 0 8px;font-weight:700;">
            <i class="fas fa-ban"></i> ${rejected.length} Rejected
        </div>`;
        html += rejected.map(candidateRow).join('');
    }
    el.innerHTML = html;
}

// full FA class incl. family — linux/windows are BRAND icons (fab), the rest solid (fas).
const _OS_ICONS = {routeros:'fas fa-dharmachakra',linux:'fab fa-linux',windows:'fab fa-windows',cisco:'fas fa-network-wired',generic:'fas fa-server',ping:'fas fa-satellite-dish',mikrotik:'fas fa-dharmachakra'};

function candidateRow(c) {
    const colors = {pending:'var(--warn)',imported:'var(--up)',rejected:'#444'};
    const icons  = {pending:'fa-clock',imported:'fa-check-circle',rejected:'fa-ban'};
    const ic = _OS_ICONS[c.os_guess] || 'fas fa-server';
    const snmpBadge = c.snmp_community
        ? `<span style="font-size:9px;background:rgba(77,163,255,.12);color:var(--accent);border-radius:4px;padding:1px 7px;white-space:nowrap;">${escHtml(c.snmp_community)} / ${escHtml(c.snmp_version||'v2c')}</span>`
        : `<span style="font-size:9px;background:rgba(255,255,255,.04);color:#555;border-radius:4px;padding:1px 7px;">no SNMP</span>`;

    let actions = '';
    if (c.status === 'pending') {
        actions = `
            <button class="btn btn-success btn-sm" style="padding:3px 10px;white-space:nowrap;" onclick="importCandidate(${c.id})">
                <i class="fas fa-plus"></i> Import
            </button>
            <button class="btn btn-sm" style="padding:3px 8px;border-color:#555;color:#555;" onclick="rejectCandidate(${c.id})" title="Reject">
                <i class="fas fa-ban"></i>
            </button>`;
    } else if (c.status === 'rejected') {
        actions = `<button class="btn btn-sm" style="padding:3px 8px;border-color:#555;color:#555;white-space:nowrap;" onclick="importCandidate(${c.id})">
            <i class="fas fa-undo"></i> Import
        </button>`;
    } else {
        actions = `<span style="font-size:10px;color:var(--up);"><i class="fas fa-check"></i> In system</span>`;
    }

    const descr = (c.sys_descr || '').substring(0, 80);
    return `<div id="cand-${c.id}" style="display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:8px;
        margin-bottom:5px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.05);transition:.2s;">
        <i class="${ic}" style="color:#4da3ff;font-size:12px;width:14px;text-align:center;flex-shrink:0;"></i>
        <div style="min-width:110px;font-family:monospace;font-size:12px;color:#4da3ff;flex-shrink:0;">${escHtml(c.ip_address)}</div>
        <div style="flex:1;min-width:0;">
            <div style="font-size:12px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                ${escHtml(c.sys_name || '(no SNMP response)')}
            </div>
            ${descr ? `<div style="font-size:10px;color:#666;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escHtml(descr)}</div>` : ''}
        </div>
        ${snmpBadge}
        <div style="display:flex;gap:5px;flex-shrink:0;">${actions}</div>
    </div>`;
}

async function importCandidate(id) {
    const el = document.getElementById('cand-' + id);
    if (el) el.style.opacity = '0.5';
    const r = await fetch('net_mon_config.php?api=import_candidate', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({id})
    }).then(r=>r.json()).catch(()=>({ok:false,err:'Network error'}));

    if (r.ok) {
        loadCandidates();
    } else {
        if (el) el.style.opacity = '1';
        alert(r.err || 'Import failed');
    }
}

async function rejectCandidate(id) {
    await fetch('net_mon_config.php?api=reject_candidate', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({id})
    }).then(r=>r.json()).catch(()=>{});
    loadCandidates();
}

async function clearRejected() {
    if (!confirm('Remove all rejected candidates from the list?')) return;
    await fetch('net_mon_config.php?api=clear_rejected', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({})
    }).then(r=>r.json()).catch(()=>{});
    loadCandidates();
}

<?php if ($tab === 'discovery'): ?>
document.addEventListener('DOMContentLoaded', loadCandidates);
<?php endif ?>

// ── Helpers ───────────────────────────────────────────────────────────────────
function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatSpeed(bps) {
    if (!bps) return '';
    if (bps>=1e9) return (bps/1e9).toFixed(0)+' Gbps';
    if (bps>=1e6) return (bps/1e6).toFixed(0)+' Mbps';
    if (bps>=1e3) return (bps/1e3).toFixed(0)+' Kbps';
    return bps+' bps';
}
</script>
</body>
</html>
