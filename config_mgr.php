<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Router Configuration Manager (SolarWinds NCM-style console).
//   Devices · Versions · Changes(diff) · Vendor commands. Gated by 'config_mgr'.
//   Backups run via n8n (SSH → running config) and are diffed/versioned by NEURU.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_confmgr.php';
require_once __DIR__ . '/nm_chrome.php';

nm_cm_ensure($conn);
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];

// ── JSON API ─────────────────────────────────────────────────────────────────
if (isset($_GET['api']) || isset($_POST['api'])) {
    header('Content-Type: application/json');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'config_mgr')) {
        http_response_code(403); echo json_encode(['err'=>'Unauthorized']); exit;
    }
    $api = $_GET['api'] ?? $_POST['api'];
    $isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');
    if ($isPost && (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token'])) {
        http_response_code(400); echo json_encode(['err'=>'Invalid CSRF token']); exit;
    }
    if (function_exists("session_write_close")) @session_write_close(); // free session lock before slow SSH/n8n I/O
    $esc = fn($s) => $conn->real_escape_string($s);

    try {
        switch ($api) {

        case 'bootstrap': {
            $vendors = nm_cm_vendors($conn);
            $creds = [];
            $cr = $conn->query("SELECT id,name,username,auth_type,is_default,secret_enc FROM nm_ssh_credentials ORDER BY is_default DESC, name");
            while ($cr && $x=$cr->fetch_assoc()) {
                // never expose the secret; just tell the UI whether it decrypts to a usable value
                $x['has_secret'] = (trim((string)nm_secret_decrypt($x['secret_enc'])) !== '');
                unset($x['secret_enc']);
                $creds[] = $x;
            }
            $nodes = [];
            $nr = $conn->query("SELECT id,display_name,ip_address,os_icon,ssh_cred_id FROM nm_nodes ORDER BY display_name");
            while ($nr && $x=$nr->fetch_assoc()) $nodes[] = $x;
            // webhook presence
            $wh = nm_n8n_webhook_by_slug($conn, 'config-backup');
            echo json_encode([
                'csrf'=>$_SESSION['csrf_token'],
                'vendors'=>$vendors, 'creds'=>$creds, 'nodes'=>$nodes,
                'webhook_ok'=>($wh && $wh['enabled']),
                'open_changes'=>nm_cm_open_change_count($conn),
            ]);
            break;
        }

        case 'devices': {
            $rows = [];
            $r = $conn->query("SELECT d.*, v.label vendor_label,
                                 (SELECT COUNT(*) FROM nm_config_changes c WHERE c.device_id=d.id AND c.status='open') open_changes
                               FROM nm_config_devices d LEFT JOIN nm_config_vendors v ON v.vendor_key=d.vendor_key
                               ORDER BY d.name");
            while ($r && $x=$r->fetch_assoc()) {
                $x['id']=(int)$x['id']; $x['versions']=(int)$x['versions']; $x['open_changes']=(int)$x['open_changes'];
                unset($x['last_hash']);
                $rows[] = $x;
            }
            echo json_encode(['devices'=>$rows]);
            break;
        }

        case 'device_save': {
            if (!$isPost){ http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $id      = (int)($_POST['id'] ?? 0);
            $name    = trim($_POST['name'] ?? '');
            $host    = trim($_POST['host_ip'] ?? '');
            $vendor  = trim($_POST['vendor_key'] ?? '');
            $cmdOvr  = trim($_POST['command_override'] ?? '');
            $credId  = (int)($_POST['ssh_cred_id'] ?? 0) ?: null;
            $nodeId  = (int)($_POST['node_id'] ?? 0) ?: null;
            $enabled = !empty($_POST['enabled']) ? 1 : 0;
            if ($name==='' || $host==='' || $vendor==='') { echo json_encode(['err'=>'Name, host and vendor are required']); break; }
            if (!nm_cm_vendor($conn, $vendor)) { echo json_encode(['err'=>'Unknown vendor']); break; }
            if ($id) {
                $st = $conn->prepare("UPDATE nm_config_devices SET name=?,host_ip=?,vendor_key=?,command_override=?,ssh_cred_id=?,node_id=?,enabled=? WHERE id=?");
                $st->bind_param('ssssiiii', $name,$host,$vendor,$cmdOvr,$credId,$nodeId,$enabled,$id);
                $st->execute(); $st->close();
                nm_audit($conn,'config.device_update',['target_type'=>'config_device','target_id'=>$id,'details'=>['name'=>$name,'host'=>$host,'vendor'=>$vendor]]);
            } else {
                $by = (int)($_SESSION['UID'] ?? 0) ?: null;
                $st = $conn->prepare("INSERT INTO nm_config_devices (node_id,name,host_ip,vendor_key,command_override,ssh_cred_id,enabled,created_by) VALUES (?,?,?,?,?,?,?,?)");
                $st->bind_param('issssiii', $nodeId,$name,$host,$vendor,$cmdOvr,$credId,$enabled,$by);
                $st->execute(); $id=$st->insert_id; $st->close();
                nm_audit($conn,'config.device_create',['target_type'=>'config_device','target_id'=>$id,'details'=>['name'=>$name,'host'=>$host,'vendor'=>$vendor]]);
            }
            echo json_encode(['ok'=>true,'id'=>$id]);
            break;
        }

        case 'device_delete': {
            if (!$isPost){ http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $id = (int)($_POST['id'] ?? 0);
            if (!$id){ echo json_encode(['err'=>'Bad id']); break; }
            $conn->query("DELETE FROM nm_config_changes   WHERE device_id={$id}");
            $conn->query("DELETE FROM nm_config_snapshots WHERE device_id={$id}");
            $conn->query("DELETE FROM nm_config_devices   WHERE id={$id}");
            nm_audit($conn,'config.device_delete',['target_type'=>'config_device','target_id'=>$id]);
            echo json_encode(['ok'=>true]);
            break;
        }

        case 'backup_now': {
            if (!$isPost){ http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $id = (int)($_POST['id'] ?? 0);
            if ($id) {
                $dr = $conn->query("SELECT * FROM nm_config_devices WHERE id={$id} LIMIT 1");
                $dev = $dr ? $dr->fetch_assoc() : null;
                if (!$dev){ echo json_encode(['err'=>'Device not found']); break; }
                nm_audit($conn,'config.backup',['target_type'=>'config_device','target_id'=>$id,'details'=>['trigger'=>'manual']]);
                echo json_encode(nm_cm_backup_device($conn, $dev, 'manual'));
            } else {
                nm_audit($conn,'config.backup',['target_type'=>'config_device','target_id'=>'all','details'=>['trigger'=>'manual']]);
                echo json_encode(nm_cm_backup_all($conn, 'manual'));
            }
            break;
        }

        case 'snapshots': {
            $did = (int)($_GET['device'] ?? 0);
            $rows = [];
            $r = $conn->query("SELECT id,captured_at,sha256,size_bytes,line_count,source FROM nm_config_snapshots
                               WHERE device_id={$did} ORDER BY captured_at DESC, id DESC LIMIT 200");
            while ($r && $x=$r->fetch_assoc()){ $x['id']=(int)$x['id']; $x['sha_short']=substr($x['sha256'],0,10); unset($x['sha256']); $rows[]=$x; }
            echo json_encode(['snapshots'=>$rows]);
            break;
        }

        case 'snapshot': {
            $sid = (int)($_GET['id'] ?? 0);
            $r = $conn->query("SELECT s.*, d.name FROM nm_config_snapshots s JOIN nm_config_devices d ON d.id=s.device_id WHERE s.id={$sid} LIMIT 1");
            $s = $r ? $r->fetch_assoc() : null;
            if (!$s){ http_response_code(404); echo json_encode(['err'=>'Not found']); break; }
            echo json_encode(['snapshot'=>['id'=>(int)$s['id'],'name'=>$s['name'],'captured_at'=>$s['captured_at'],
                'line_count'=>(int)$s['line_count'],'config_text'=>$s['config_text']]]);
            break;
        }

        case 'diff': {
            $a = (int)($_GET['a'] ?? 0); $b = (int)($_GET['b'] ?? 0);
            $ta = $conn->query("SELECT config_text FROM nm_config_snapshots WHERE id={$a} LIMIT 1");
            $tb = $conn->query("SELECT config_text FROM nm_config_snapshots WHERE id={$b} LIMIT 1");
            $A = $ta && ($x=$ta->fetch_assoc()) ? (string)$x['config_text'] : '';
            $B = $tb && ($x=$tb->fetch_assoc()) ? (string)$x['config_text'] : '';
            echo json_encode(['diff'=>nm_cm_diff($A,$B)]);
            break;
        }

        case 'changes': {
            $status = $_GET['status'] ?? 'open';
            $w = $status==='all' ? '' : "WHERE c.status='".$esc($status)."'";
            $rows = [];
            $r = $conn->query("SELECT c.id,c.device_id,c.snapshot_id,c.prev_snapshot_id,c.detected_at,c.added,c.removed,c.status,c.acked_by,c.acked_at,
                                 d.name,d.host_ip,d.vendor_key
                               FROM nm_config_changes c JOIN nm_config_devices d ON d.id=c.device_id
                               {$w} ORDER BY c.detected_at DESC LIMIT 200");
            while ($r && $x=$r->fetch_assoc()){ foreach(['id','device_id','snapshot_id','prev_snapshot_id','added','removed'] as $k) $x[$k]=(int)$x[$k]; $rows[]=$x; }
            echo json_encode(['changes'=>$rows]);
            break;
        }

        case 'change': {
            $id = (int)($_GET['id'] ?? 0);
            $r = $conn->query("SELECT c.*, d.name,d.host_ip,d.vendor_key FROM nm_config_changes c JOIN nm_config_devices d ON d.id=c.device_id WHERE c.id={$id} LIMIT 1");
            $c = $r ? $r->fetch_assoc() : null;
            if (!$c){ http_response_code(404); echo json_encode(['err'=>'Not found']); break; }
            echo json_encode(['change'=>$c]);
            break;
        }

        case 'change_ack': {
            if (!$isPost){ http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $id = (int)($_POST['id'] ?? 0); $st = $_POST['status'] ?? '';
            if (!$id || !in_array($st,['acknowledged','resolved','open'],true)){ echo json_encode(['err'=>'Bad input']); break; }
            $by = $_SESSION['username'] ?? '';
            $q = $conn->prepare("UPDATE nm_config_changes SET status=?, acked_by=?, acked_at=NOW() WHERE id=?");
            $q->bind_param('ssi', $st, $by, $id); $q->execute(); $q->close();
            nm_audit($conn,'config.change_'.$st,['target_type'=>'config_change','target_id'=>$id]);
            echo json_encode(['ok'=>true]);
            break;
        }

        // for the dashboard alert injector
        case 'dash_changes': {
            echo json_encode(['changes'=>nm_cm_open_changes($conn, 25)]);
            break;
        }

        case 'vendor_save': {
            if (!$isPost){ http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $key = trim($_POST['vendor_key'] ?? '');
            $label = trim($_POST['label'] ?? '');
            $cmd = trim($_POST['command'] ?? '');
            $ign = trim($_POST['ignore_regex'] ?? '');
            $en = !empty($_POST['enabled']) ? 1 : 0;
            if (!preg_match('/^[a-z0-9_\-]{2,40}$/',$key)){ echo json_encode(['err'=>'Vendor key: 2-40 lowercase letters/digits/_/-']); break; }
            if ($label===''){ echo json_encode(['err'=>'Label required']); break; }
            $st = $conn->prepare("INSERT INTO nm_config_vendors (vendor_key,label,command,ignore_regex,enabled) VALUES (?,?,?,?,?)
                                  ON DUPLICATE KEY UPDATE label=VALUES(label),command=VALUES(command),ignore_regex=VALUES(ignore_regex),enabled=VALUES(enabled)");
            $st->bind_param('ssssi',$key,$label,$cmd,$ign,$en); $st->execute(); $st->close();
            nm_audit($conn,'config.vendor_save',['target_type'=>'config_vendor','target_id'=>$key]);
            echo json_encode(['ok'=>true]);
            break;
        }

        default:
            http_response_code(400); echo json_encode(['err'=>'Unknown action']);
        }
    } catch (\Throwable $e) {
        http_response_code(500); echo json_encode(['err'=>'Server error: '.$e->getMessage()]);
    }
    exit;
}

// ── HTML page ────────────────────────────────────────────────────────────────
include('check.php');
if (!checkAccess($conn, 'config_mgr')) { header('Location: /denied_access.php?page=config_mgr'); exit; }
include('header.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Config Manager | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#4da3ff;--up:#2ecc71;--down:#e74c3c;--warn:#f39c12;--mut:#8a909a;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#000;color:#fff;overflow-x:hidden;}
.wrap{max-width:1600px;margin:0 auto;padding:18px 22px 60px;}
.glass-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:18px;}
h2{margin:0 0 14px;font-size:15px;color:var(--accent);display:flex;align-items:center;gap:9px;}
.btn{padding:8px 15px;border-radius:9px;border:1px solid var(--border);background:rgba(255,255,255,.05);color:#cfd3da;font-size:12.5px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:7px;transition:.18s;text-decoration:none;}
.btn:hover{border-color:var(--accent);color:#fff;}
.btn-primary{background:rgba(77,163,255,.15);border-color:var(--accent);color:var(--accent);}
.btn-primary:hover{background:var(--accent);color:#000;}
.btn-success{background:rgba(46,204,113,.15);border-color:var(--up);color:var(--up);}
.btn-success:hover{background:var(--up);color:#000;}
.btn-danger{background:rgba(231,76,60,.12);border-color:var(--down);color:var(--down);}
.btn-danger:hover{background:var(--down);color:#fff;}
.btn-sm{padding:5px 9px;font-size:11px;border-radius:7px;}
.form-input,.form-select,textarea.form-input{background:rgba(255,255,255,0.07);border:1px solid var(--border);color:#fff;padding:9px 13px;border-radius:8px;font-size:13px;outline:none;width:100%;box-sizing:border-box;font-family:inherit;}
.form-select{background:rgba(20,30,50,0.95);}
.form-input:focus,.form-select:focus{border-color:var(--accent);}
.fld{display:flex;flex-direction:column;gap:5px;margin-bottom:12px;}
.fld label{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--mut);}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;color:var(--mut);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.6px;padding:9px 11px;border-bottom:1px solid var(--border);}
td{padding:9px 11px;border-bottom:1px solid rgba(255,255,255,.05);vertical-align:middle;}
tr:hover td{background:rgba(255,255,255,.025);}
.mut{color:var(--mut);font-size:11px;}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:#aab;}
.tag{font-size:10px;padding:2px 9px;border-radius:6px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;display:inline-flex;align-items:center;gap:5px;}
.t-ok{background:rgba(46,204,113,.16);color:#2ecc71;} .t-changed{background:rgba(243,156,18,.18);color:#f5b73d;}
.t-failed{background:rgba(231,76,60,.18);color:#e74c3c;} .t-never{background:rgba(255,255,255,.08);color:#9aa;}
.t-vendor{background:rgba(77,163,255,.14);color:#7fc0ff;}
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px;}
.stat-card{background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:14px;padding:15px 18px;}
.stat-card .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--mut);}
.stat-card .val{font-size:28px;font-weight:800;margin-top:3px;}
.sw{position:relative;display:inline-block;width:42px;height:23px;flex:none;}
.sw input{opacity:0;width:0;height:0;}
.sw .sl{position:absolute;cursor:pointer;inset:0;background:#3a3f4b;border-radius:23px;transition:.25s;}
.sw .sl::before{content:'';position:absolute;width:17px;height:17px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.25s;}
.sw input:checked+.sl{background:var(--up);}
.sw input:checked+.sl::before{transform:translateX(19px);}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(4px);display:none;align-items:flex-start;justify-content:center;z-index:1000;padding:34px 16px;overflow-y:auto;}
.modal-bg.show{display:flex;}
.modal{background:#0d1119;border:1px solid var(--border);border-radius:16px;width:100%;max-width:680px;padding:22px 24px;box-shadow:0 24px 70px rgba(0,0,0,.6);}
.modal.wide{max-width:1080px;}
.modal h3{margin:0 0 4px;font-size:16px;display:flex;align-items:center;gap:9px;}
.modal .mh-sub{color:var(--mut);font-size:12px;margin-bottom:16px;}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px;}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.hidden{display:none!important;}
/* diff viewer */
.diffbox{background:#070a0f;border:1px solid var(--border);border-radius:10px;padding:0;max-height:62vh;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.5;}
.diffbox .dl{display:block;white-space:pre;padding:0 12px;}
.diffbox .da{background:rgba(46,204,113,.13);color:#7ee2a4;}
.diffbox .dr{background:rgba(231,76,60,.13);color:#f29b91;}
.diffbox .dh{color:#6aa0d8;background:rgba(77,163,255,.07);}
.diffbox .dc{color:#7c8696;}
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(120%);background:#11151d;border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:10px;padding:12px 18px;font-size:13px;z-index:2000;transition:.3s;max-width:90vw;}
#toast.show{transform:translateX(-50%) translateY(0);} #toast.ok{border-left-color:var(--up);} #toast.bad{border-left-color:var(--down);}
.warnbar{background:rgba(243,156,18,.12);border:1px solid rgba(243,156,18,.4);color:#f5b73d;border-radius:10px;padding:10px 14px;font-size:12.5px;margin-bottom:16px;display:flex;align-items:center;gap:10px;}
</style>
</head>
<body>
<div class="wrap">
<?php nm_page_header('Config', 'Manager', 'Router Configuration Backup &amp; Drift', 'fa-solid fa-file-shield'); ?>
<?php
nm_module_tabs([
    ['icon'=>'fa-solid fa-server','label'=>'Devices','href'=>'#devices','active'=>true],
    ['icon'=>'fa-solid fa-code-compare','label'=>'Changes','href'=>'#changes','active'=>false],
    ['icon'=>'fa-solid fa-terminal','label'=>'Vendor Commands','href'=>'#vendors','active'=>false],
]);
?>

<div id="sec-warn" class="warnbar hidden" style="background:rgba(231,76,60,.12);border-color:rgba(231,76,60,.4);color:#f29b91;">
  <i class="fa-solid fa-key"></i>
  <span>SSH credential(s) with <b>no readable password</b>: <b id="sec-warn-list"></b>. Backups using them will fail
  (n8n gets an empty password). Re-type the password in
  <a href="net_mon_config.php?tab=integrations" style="color:#f29b91;">Config → Integrations → SSH Credentials</a> to re-encrypt it.</span>
</div>

<!-- ════ DEVICES ════ -->
<section id="tab-devices">
  <div class="stat-row">
    <div class="stat-card"><div class="lbl">Devices</div><div class="val" id="st-dev">—</div></div>
    <div class="stat-card"><div class="lbl">Backed Up</div><div class="val" style="color:var(--up)" id="st-ok">—</div></div>
    <div class="stat-card"><div class="lbl">Failed</div><div class="val" style="color:var(--down)" id="st-fail">—</div></div>
    <div class="stat-card"><div class="lbl">Open Changes</div><div class="val" style="color:var(--warn)" id="st-chg">—</div></div>
  </div>
  <div class="glass-card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
      <h2 style="margin:0;"><i class="fa-solid fa-server"></i> Managed Devices</h2>
      <div style="display:flex;gap:9px;">
        <button class="btn" onclick="backupAll()"><i class="fa-solid fa-cloud-arrow-down"></i> Backup all now</button>
        <button class="btn btn-primary" onclick="openDevice()"><i class="fa-solid fa-plus"></i> Add Device</button>
      </div>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Device</th><th>Host</th><th>Vendor</th><th>Status</th><th>Last Backup</th><th>Versions</th><th style="text-align:right;">Actions</th></tr></thead>
        <tbody id="dev-tbody"><tr><td colspan="7" style="text-align:center;color:var(--mut);padding:30px;">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>
</section>

<!-- ════ CHANGES ════ -->
<section id="tab-changes" class="hidden">
  <div class="glass-card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
      <h2 style="margin:0;"><i class="fa-solid fa-code-compare"></i> Configuration Changes</h2>
      <select class="form-select" id="chg-filter" style="width:auto;" onchange="loadChanges()">
        <option value="open">Open</option><option value="all">All</option>
        <option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option>
      </select>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Detected</th><th>Device</th><th>Change</th><th>Status</th><th style="text-align:right;">Actions</th></tr></thead>
        <tbody id="chg-tbody"><tr><td colspan="5" style="text-align:center;color:var(--mut);padding:30px;">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>
</section>

<!-- ════ VENDORS ════ -->
<section id="tab-vendors" class="hidden">
  <div class="glass-card">
    <h2><i class="fa-solid fa-terminal"></i> Vendor Commands &amp; Filters</h2>
    <div class="mut" style="margin-bottom:14px;">The command run over SSH per brand to dump the running config, and the volatile-line
      filters (one regex per line) that are stripped before comparison so timestamps don't register as drift.</div>
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Brand</th><th>Key</th><th>Command</th><th>Filters</th><th>On</th><th></th></tr></thead>
        <tbody id="ven-tbody"></tbody>
      </table>
    </div>
  </div>
</section>
</div>

<!-- device modal -->
<div class="modal-bg" id="dev-modal"><div class="modal">
  <h3><i class="fa-solid fa-server"></i> <span id="dm-title">Add Device</span></h3>
  <div class="mh-sub">Pick a monitored node to autofill, or enter a host manually. The command comes from the vendor (override per-device if needed).</div>
  <input type="hidden" id="dm-id"><input type="hidden" id="dm-node">
  <div class="fld"><label>Autofill from monitored node</label>
    <select class="form-select" id="dm-pick" onchange="pickNode()"><option value="">— manual entry —</option></select></div>
  <div class="row2">
    <div class="fld"><label>Display name</label><input class="form-input" id="dm-name" placeholder="CORE-ROUTER-MIKROTIK"></div>
    <div class="fld"><label>Host / IP</label><input class="form-input" id="dm-host" placeholder="192.168.0.253"></div>
  </div>
  <div class="row2">
    <div class="fld"><label>Vendor / brand</label><select class="form-select" id="dm-vendor" onchange="vendorCmdHint()"></select></div>
    <div class="fld"><label>SSH credential</label><select class="form-select" id="dm-cred"></select>
      <span id="dm-cred-warn" class="hidden" style="color:#f29b91;font-size:10.5px;"><i class="fa-solid fa-key"></i> This credential has no readable password — re-type it in Config → SSH Credentials or the backup will fail.</span></div>
  </div>
  <div class="fld"><label>Command override <span class="mut" id="dm-cmdhint"></span></label>
    <input class="form-input mono" id="dm-cmd" placeholder="(leave blank to use the vendor default)"></div>
  <div style="display:flex;align-items:center;gap:10px;margin-top:4px;">
    <label class="sw"><input type="checkbox" id="dm-enabled" checked><span class="sl"></span></label>
    <span class="mut">Enabled — include in daily backup</span>
  </div>
  <div class="modal-actions">
    <button class="btn" onclick="closeM('dev-modal')">Cancel</button>
    <button class="btn btn-success" onclick="saveDevice()"><i class="fa-solid fa-check"></i> Save</button>
  </div>
</div></div>

<!-- diff / snapshot modal -->
<div class="modal-bg" id="diff-modal"><div class="modal wide">
  <h3><i class="fa-solid fa-code-compare"></i> <span id="df-title">Diff</span></h3>
  <div class="mh-sub" id="df-sub"></div>
  <div class="diffbox" id="df-body"></div>
  <div class="modal-actions" id="df-actions">
    <button class="btn" onclick="closeM('diff-modal')">Close</button>
  </div>
</div></div>

<!-- vendor edit modal -->
<div class="modal-bg" id="ven-modal"><div class="modal">
  <h3><i class="fa-solid fa-terminal"></i> <span id="vm-title">Vendor</span></h3>
  <div class="mh-sub">Command run over SSH to export the running config + volatile-line filters (one regex per line).</div>
  <input type="hidden" id="vm-key-h">
  <div class="row2">
    <div class="fld"><label>Key</label><input class="form-input mono" id="vm-key" placeholder="mikrotik"></div>
    <div class="fld"><label>Label</label><input class="form-input" id="vm-label" placeholder="MikroTik RouterOS"></div>
  </div>
  <div class="fld"><label>Command</label><input class="form-input mono" id="vm-cmd" placeholder="/export"></div>
  <div class="fld"><label>Ignore filters (one regex per line)</label><textarea class="form-input mono" id="vm-ign" rows="4" placeholder="^# .* by RouterOS"></textarea></div>
  <div style="display:flex;align-items:center;gap:10px;"><label class="sw"><input type="checkbox" id="vm-en" checked><span class="sl"></span></label><span class="mut">Enabled</span></div>
  <div class="modal-actions"><button class="btn" onclick="closeM('ven-modal')">Cancel</button>
    <button class="btn btn-success" onclick="saveVendor()"><i class="fa-solid fa-check"></i> Save</button></div>
</div></div>

<div id="toast"></div>
<script>
const CSRF = <?= json_encode($CSRF) ?>;
let BOOT=null, DEVICES=[], VENDORS=[];
const FOCUS_CHANGE = new URLSearchParams(location.search).get('focus');

function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function toast(m,k){const t=document.getElementById('toast');t.className=k||'';t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}
function closeM(id){document.getElementById(id).classList.remove('show');}
async function api(action,data){
  let url='config_mgr.php?api='+action, opt={};
  if(data){ const fd=new FormData(); fd.append('api',action.split('&')[0]); fd.append('csrf',CSRF); for(const k in data) fd.append(k,data[k]); opt={method:'POST',body:fd}; }
  const r=await fetch(url,opt); let j; try{j=await r.json();}catch(e){j={err:'Bad response'};}
  if(!r.ok||j.err){ toast(j.err||('HTTP '+r.status),'bad'); throw new Error(j.err||r.status); }
  return j;
}
// tabs
document.querySelectorAll('.nm-tab').forEach(t=>t.addEventListener('click',e=>{
  e.preventDefault();
  document.querySelectorAll('.nm-tab').forEach(x=>x.classList.remove('is-active')); t.classList.add('is-active');
  const id=t.getAttribute('href').slice(1);
  ['devices','changes','vendors'].forEach(s=>document.getElementById('tab-'+s).classList.toggle('hidden',s!==id));
  if(id==='changes') loadChanges(); if(id==='vendors') renderVendors();
}));

async function boot(){
  BOOT=await api('bootstrap'); VENDORS=BOOT.vendors;
  // vendor select
  document.getElementById('dm-vendor').innerHTML = VENDORS.map(v=>`<option value="${esc(v.vendor_key)}">${esc(v.label)}</option>`).join('');
  // cred select — flag credentials whose stored secret is empty/unreadable
  document.getElementById('dm-cred').innerHTML = '<option value="">— default credential —</option>' +
    BOOT.creds.map(c=>`<option value="${c.id}" data-secret="${c.has_secret?1:0}">${esc(c.name)} (${esc(c.username)})${c.is_default==1?' ★':''}${c.has_secret?'':' ⚠ no password'}</option>`).join('');
  document.getElementById('dm-cred').addEventListener('change', credSecretHint);
  // global banner if ANY cred is missing its secret (the post-key-regen case)
  const noSecret = BOOT.creds.filter(c=>!c.has_secret).map(c=>c.name);
  const sb=document.getElementById('sec-warn');
  if(noSecret.length){ sb.classList.remove('hidden');
    document.getElementById('sec-warn-list').textContent = noSecret.join(', '); }
  else sb.classList.add('hidden');
  // node picker
  document.getElementById('dm-pick').innerHTML = '<option value="">— manual entry —</option>' +
    BOOT.nodes.map(n=>`<option value="${n.id}" data-name="${esc(n.display_name)}" data-ip="${esc(n.ip_address)}" data-os="${esc(n.os_icon)}" data-cred="${n.ssh_cred_id||''}">${esc(n.display_name)} · ${esc(n.ip_address)}</option>`).join('');
  await loadDevices();
  if(FOCUS_CHANGE){ document.querySelector('.nm-tab[href="#changes"]').click(); setTimeout(()=>viewChange(+FOCUS_CHANGE),300); }
}

async function loadDevices(){
  const d=await api('devices'); DEVICES=d.devices;
  let ok=0,fail=0,chg=0;
  DEVICES.forEach(x=>{ if(x.last_status==='ok'||x.last_status==='changed')ok++; if(x.last_status==='failed')fail++; chg+=x.open_changes; });
  document.getElementById('st-dev').textContent=DEVICES.length;
  document.getElementById('st-ok').textContent=ok;
  document.getElementById('st-fail').textContent=fail;
  document.getElementById('st-chg').textContent=chg;
  const tb=document.getElementById('dev-tbody');
  if(!DEVICES.length){ tb.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--mut);padding:30px;">No devices yet — click “Add Device”.</td></tr>'; return; }
  tb.innerHTML=DEVICES.map(x=>{
    const stc = {ok:'t-ok',changed:'t-changed',failed:'t-failed',never:'t-never'}[x.last_status]||'t-never';
    const stTxt = x.last_status==='ok' && x.open_changes>0 ? 'changed' : x.last_status;
    const err = x.last_status==='failed' && x.last_error ? ` title="${esc(x.last_error)}"` : '';
    return `<tr>
      <td><b>${esc(x.name)}</b>${x.open_changes>0?` <span class="tag t-changed">${x.open_changes} drift</span>`:''}</td>
      <td class="mono">${esc(x.host_ip)}</td>
      <td><span class="tag t-vendor">${esc(x.vendor_label||x.vendor_key)}</span></td>
      <td><span class="tag ${stc}"${err}>${esc(stTxt)}</span></td>
      <td class="mono">${x.last_backup_at?esc(x.last_backup_at):'<span class="mut">never</span>'}</td>
      <td>${x.versions>0?`<a href="#" onclick="history(${x.id},'${esc(x.name)}');return false;" style="color:var(--accent);">${x.versions}</a>`:'<span class="mut">0</span>'}</td>
      <td style="text-align:right;white-space:nowrap;">
        <button class="btn btn-sm" title="Backup now" onclick="backupOne(${x.id})"><i class="fa-solid fa-cloud-arrow-down"></i></button>
        <button class="btn btn-sm" title="Latest config" onclick="viewLatest(${x.id})" ${x.versions>0?'':'disabled style=opacity:.4'}><i class="fa-solid fa-file-lines"></i></button>
        <button class="btn btn-sm" title="Edit" onclick="openDevice(${x.id})"><i class="fa-solid fa-pen"></i></button>
        <button class="btn btn-sm btn-danger" title="Delete" onclick="delDevice(${x.id})"><i class="fa-solid fa-trash"></i></button>
      </td></tr>`;
  }).join('');
}

function vendorCmdHint(){ const v=VENDORS.find(x=>x.vendor_key===document.getElementById('dm-vendor').value); document.getElementById('dm-cmdhint').textContent = v? '→ default: '+(v.command||'(none)') : ''; }
function credSecretHint(){ const o=document.getElementById('dm-cred').selectedOptions[0];
  const bad = o && o.value && o.dataset.secret==='0';
  document.getElementById('dm-cred-warn').classList.toggle('hidden', !bad); }
function pickNode(){
  const o=document.getElementById('dm-pick').selectedOptions[0]; if(!o||!o.value) return;
  document.getElementById('dm-name').value=o.dataset.name||'';
  document.getElementById('dm-host').value=o.dataset.ip||'';
  document.getElementById('dm-node').value=o.value;
  // guess vendor from os
  const os=(o.dataset.os||'').toLowerCase();
  const guess={routeros:'mikrotik',mikrotik:'mikrotik',cisco:'cisco_ios',arista:'arista',juniper:'juniper',fortinet:'fortinet',linux:'linux'}[os]||'generic';
  document.getElementById('dm-vendor').value=guess; vendorCmdHint();
  if(o.dataset.cred) document.getElementById('dm-cred').value=o.dataset.cred;
}
function openDevice(id){
  const m=document.getElementById('dev-modal');
  document.getElementById('dm-pick').value=''; document.getElementById('dm-node').value='';
  if(id){
    const x=DEVICES.find(d=>d.id===id);
    document.getElementById('dm-title').textContent='Edit Device';
    document.getElementById('dm-id').value=id;
    document.getElementById('dm-name').value=x.name; document.getElementById('dm-host').value=x.host_ip;
    document.getElementById('dm-vendor').value=x.vendor_key; document.getElementById('dm-cred').value=x.ssh_cred_id||'';
    document.getElementById('dm-cmd').value=x.command_override||''; document.getElementById('dm-enabled').checked=x.enabled==1;
    document.getElementById('dm-node').value=x.node_id||'';
  } else {
    document.getElementById('dm-title').textContent='Add Device';
    ['dm-id','dm-name','dm-host','dm-cmd'].forEach(i=>document.getElementById(i).value='');
    document.getElementById('dm-cred').value=''; document.getElementById('dm-enabled').checked=true;
    if(VENDORS.length) document.getElementById('dm-vendor').value=VENDORS.find(v=>v.vendor_key==='mikrotik')?'mikrotik':VENDORS[0].vendor_key;
  }
  vendorCmdHint(); m.classList.add('show');
}
async function saveDevice(){
  const data={ id:document.getElementById('dm-id').value, name:document.getElementById('dm-name').value.trim(),
    host_ip:document.getElementById('dm-host').value.trim(), vendor_key:document.getElementById('dm-vendor').value,
    command_override:document.getElementById('dm-cmd').value.trim(), ssh_cred_id:document.getElementById('dm-cred').value,
    node_id:document.getElementById('dm-node').value, enabled:document.getElementById('dm-enabled').checked?1:'' };
  await api('device_save',data); toast('Device saved','ok'); closeM('dev-modal'); loadDevices();
}
async function delDevice(id){ const x=DEVICES.find(d=>d.id===id);
  if(!confirm('Delete "'+x.name+'" and all its stored config versions? This cannot be undone.')) return;
  await api('device_delete',{id}); toast('Deleted','ok'); loadDevices();
}
async function backupOne(id){ toast('Backing up…'); try{ const r=await api('backup_now',{id});
  toast(r.ok?('Backup: '+(r.status||'ok')+(r.changed?` (+${r.added}/-${r.removed})`:'')):('Failed: '+(r.error||'?')), r.ok?'ok':'bad'); }catch(e){} loadDevices(); }
async function backupAll(){ toast('Backing up all devices…'); try{ const r=await api('backup_now',{});
  toast(`Done — ${r.ok}/${r.total} ok, ${r.changed} changed, ${r.failed} failed`, r.failed? 'bad':'ok'); }catch(e){} loadDevices(); }

// version history → reuse diff modal
async function history(id,name){
  const d=await api('snapshots&device='+id);
  document.getElementById('df-title').textContent='Versions — '+name;
  document.getElementById('df-sub').textContent=d.snapshots.length+' stored version(s). Click a version to view; pick two and Compare.';
  let rows=d.snapshots.map((s,i)=>`<label class="dl dc" style="display:flex;gap:10px;align-items:center;padding:5px 12px;cursor:pointer;">
      <input type="checkbox" class="vchk" value="${s.id}" onchange="limitChk(this)">
      <span class="mono" style="color:#9bc;min-width:150px;">${esc(s.captured_at)}</span>
      <span class="mut">${s.line_count} lines · ${esc(s.source)} · ${s.sha_short}</span>
      <a href="#" onclick="viewSnap(${s.id});return false;" style="margin-left:auto;color:var(--accent);">view</a></label>`).join('');
  document.getElementById('df-body').innerHTML='<div style="padding:8px 0;">'+rows+'</div>';
  document.getElementById('df-actions').innerHTML='<button class="btn btn-primary" onclick="compareChecked()"><i class="fa-solid fa-code-compare"></i> Compare selected</button><button class="btn" onclick="closeM(\'diff-modal\')">Close</button>';
  document.getElementById('diff-modal').classList.add('show');
}
function limitChk(cb){ const c=[...document.querySelectorAll('.vchk:checked')]; if(c.length>2) cb.checked=false; }
async function compareChecked(){ const c=[...document.querySelectorAll('.vchk:checked')].map(x=>x.value);
  if(c.length!==2){ toast('Select exactly two versions','bad'); return; }
  const d=await api(`diff&a=${c[1]}&b=${c[0]}`); renderDiff(d.diff,'Compare versions'); }
async function viewSnap(id){ const d=await api('snapshot&id='+id);
  document.getElementById('df-title').textContent='Config — '+esc(d.snapshot.name);
  document.getElementById('df-sub').textContent=d.snapshot.captured_at+' · '+d.snapshot.line_count+' lines';
  document.getElementById('df-body').innerHTML='<div class="dl">'+esc(d.snapshot.config_text)+'</div>';
  document.getElementById('df-actions').innerHTML='<button class="btn" onclick="closeM(\'diff-modal\')">Close</button>';
  document.getElementById('diff-modal').classList.add('show');
}
async function viewLatest(id){ const x=DEVICES.find(d=>d.id===id); if(!x||!x.last_snapshot_id){ toast('No version yet','bad'); return; } viewSnap(x.last_snapshot_id); }

function renderDiff(diff,title){
  document.getElementById('df-title').textContent=title||'Diff';
  const html=(diff.diff||'(no differences)').split('\n').map(l=>{
    let c='dc'; if(l.startsWith('@@'))c='dh'; else if(l.startsWith('+'))c='da'; else if(l.startsWith('-'))c='dr';
    return `<span class="dl ${c}">${esc(l)||' '}</span>`;
  }).join('');
  document.getElementById('df-sub').textContent=`+${diff.added||0} added · -${diff.removed||0} removed`;
  document.getElementById('df-body').innerHTML=html;
  document.getElementById('df-actions').innerHTML='<button class="btn" onclick="closeM(\'diff-modal\')">Close</button>';
  document.getElementById('diff-modal').classList.add('show');
}

// ════ CHANGES ════
async function loadChanges(){
  const st=document.getElementById('chg-filter').value;
  const d=await api('changes&status='+st);
  const tb=document.getElementById('chg-tbody');
  if(!d.changes.length){ tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--mut);padding:30px;">No changes.</td></tr>'; return; }
  tb.innerHTML=d.changes.map(c=>{
    const stc={open:'t-changed',acknowledged:'t-vendor',resolved:'t-ok'}[c.status]||'t-never';
    return `<tr>
      <td class="mono">${esc(c.detected_at)}</td>
      <td><b>${esc(c.name)}</b><div class="mut">${esc(c.host_ip)} · ${esc(c.vendor_key)}</div></td>
      <td><span style="color:var(--up)">+${c.added}</span> / <span style="color:var(--down)">-${c.removed}</span></td>
      <td><span class="tag ${stc}">${esc(c.status)}</span>${c.acked_by?`<div class="mut">${esc(c.acked_by)}</div>`:''}</td>
      <td style="text-align:right;white-space:nowrap;">
        <button class="btn btn-sm btn-primary" onclick="viewChange(${c.id})"><i class="fa-solid fa-code-compare"></i> Diff</button>
        ${c.status==='open'?`<button class="btn btn-sm" onclick="ackChange(${c.id},'acknowledged')" title="Acknowledge"><i class="fa-solid fa-eye"></i></button>`:''}
        ${c.status!=='resolved'?`<button class="btn btn-sm btn-success" onclick="ackChange(${c.id},'resolved')" title="Resolve"><i class="fa-solid fa-check"></i></button>`:''}
      </td></tr>`;
  }).join('');
}
async function viewChange(id){
  const d=await api('change&id='+id); const c=d.change;
  renderDiff({diff:c.diff_text,added:c.added,removed:c.removed}, 'Drift — '+esc(c.name)+' @ '+esc(c.detected_at));
}
async function ackChange(id,status){ await api('change_ack',{id,status}); toast(status==='resolved'?'Resolved':'Acknowledged','ok'); loadChanges(); loadDevices(); }

// ════ VENDORS ════
function renderVendors(){
  document.getElementById('ven-tbody').innerHTML=VENDORS.map(v=>`<tr>
    <td><b>${esc(v.label)}</b></td><td class="mono">${esc(v.vendor_key)}</td>
    <td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(v.command)||'<span class="mut">—</span>'}</td>
    <td class="mut">${(v.ignore_regex||'').split('\\n').filter(Boolean).length} filter(s)</td>
    <td>${v.enabled==1?'<span class="tag t-ok">on</span>':'<span class="tag t-never">off</span>'}</td>
    <td style="text-align:right;"><button class="btn btn-sm" onclick="editVendor('${esc(v.vendor_key)}')"><i class="fa-solid fa-pen"></i></button></td></tr>`).join('') +
    `<tr><td colspan="6" style="padding-top:12px;"><button class="btn btn-primary btn-sm" onclick="editVendor('')"><i class="fa-solid fa-plus"></i> Add brand</button></td></tr>`;
}
function editVendor(key){
  const v=VENDORS.find(x=>x.vendor_key===key)||{vendor_key:'',label:'',command:'',ignore_regex:'',enabled:1};
  document.getElementById('vm-title').textContent=key?('Edit '+v.label):'Add Brand';
  document.getElementById('vm-key').value=v.vendor_key; document.getElementById('vm-key').disabled=!!key;
  document.getElementById('vm-label').value=v.label; document.getElementById('vm-cmd').value=v.command;
  document.getElementById('vm-ign').value=v.ignore_regex||''; document.getElementById('vm-en').checked=v.enabled==1;
  document.getElementById('ven-modal').classList.add('show');
}
async function saveVendor(){
  const data={ vendor_key:document.getElementById('vm-key').value.trim(), label:document.getElementById('vm-label').value.trim(),
    command:document.getElementById('vm-cmd').value, ignore_regex:document.getElementById('vm-ign').value,
    enabled:document.getElementById('vm-en').checked?1:'' };
  await api('vendor_save',data); toast('Vendor saved','ok'); closeM('ven-modal');
  BOOT=await api('bootstrap'); VENDORS=BOOT.vendors; renderVendors();
  document.getElementById('dm-vendor').innerHTML = VENDORS.map(v=>`<option value="${esc(v.vendor_key)}">${esc(v.label)}</option>`).join('');
}

document.querySelectorAll('.modal-bg').forEach(m=>m.addEventListener('click',e=>{ if(e.target===m) m.classList.remove('show'); }));
boot();
</script>
</body>
</html>
