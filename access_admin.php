<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Access Control. Unified admin console for users, roles & per-user
// page permissions, plus a live activity feed. Gated by button_key 'user_admin'.
//
//   • Users tab  — create / edit / delete users, assign role, reset password,
//                  and fine-tune per-user page access (Inherit / Allow / Deny).
//   • Roles tab  — create roles + a category-grouped permission matrix that
//                  drives which pages every member of a role can reach.
//   • Activity   — recent security events from nm_audit_log (full viewer at
//                  audit_log.php).
//
//   Every mutation is audited. Lockout-proof: any change that would leave zero
//   accounts able to reach Access Control is refused (transactional check).
// ─────────────────────────────────────────────────────────────────────────────

if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';            // $conn
require_once __DIR__ . '/access_control.php';        // checkAccess() + nm_access engine
require_once __DIR__ . '/nm_access.php';
require_once __DIR__ . '/nm_audit.php';

nm_access_ensure($conn);

// CSRF token for state-changing calls (generated here if the session lacks one).
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];

// ── JSON API ─────────────────────────────────────────────────────────────────
if (isset($_GET['api']) || isset($_POST['api'])) {
    header('Content-Type: application/json');

    if (empty($_SESSION['username']) || !checkAccess($conn, 'user_admin')) {
        http_response_code(403);
        echo json_encode(['err' => 'Unauthorized']);
        exit;
    }

    $api    = $_GET['api'] ?? $_POST['api'];
    $isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');

    // CSRF on every mutating call.
    if ($isPost) {
        if (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token']) {
            http_response_code(400);
            echo json_encode(['err' => 'Invalid CSRF token']);
            exit;
        }
    }

    $catalog    = nm_perm_catalog();
    $allKeys    = nm_perm_keys();
    $catKeys    = array_column(array_map(fn($r)=>['k'=>$r[0]], $catalog), 'k');
    $valid_key  = fn($k) => in_array($k, $allKeys, true);
    $valid_role = function($r) { return (bool)preg_match('/^[A-Za-z0-9_\-]{2,20}$/', $r); };
    $me_uid     = (int)($_SESSION['UID'] ?? 0);

    // Build the catalog payload (grouped) the front-end renders from.
    $catalog_payload = array_map(fn($r) => [
        'key'=>$r[0], 'label'=>$r[1], 'category'=>$r[2], 'icon'=>$r[3], 'page'=>$r[4],
    ], $catalog);

    try {
        switch ($api) {

        // ── Read: everything the page needs on load ──────────────────────────
        case 'bootstrap': {
            // roles
            $roles = [];
            $rr = $conn->query("SELECT role_name, COUNT(*) tot, COALESCE(SUM(enabled),0) granted
                                FROM role_profiles GROUP BY role_name ORDER BY role_name");
            while ($x = $rr->fetch_assoc()) {
                $roles[] = ['role'=>$x['role_name'], 'total'=>(int)$x['tot'], 'granted'=>(int)$x['granted']];
            }
            echo json_encode([
                'csrf'    => $_SESSION['csrf_token'],
                'me'      => ['uid'=>$me_uid, 'username'=>$_SESSION['username'], 'role'=>$_SESSION['role'] ?? ''],
                'catalog' => $catalog_payload,
                'categories' => nm_perm_categories(),
                'roles'   => $roles,
                'admin_count' => nm_access_admin_count($conn),
            ]);
            break;
        }

        // ── Read: user list with role, last login, override count ────────────
        case 'users': {
            $users = [];
            $sql = "SELECT u.UID, u.USERNAME, u.name, u.email, u.role, u.last_login,
                           (SELECT COUNT(*) FROM nm_user_perms p WHERE p.uid=u.UID) AS overrides
                    FROM users u ORDER BY u.UID";
            $res = $conn->query($sql);
            while ($x = $res->fetch_assoc()) {
                $x['UID'] = (int)$x['UID'];
                $x['overrides'] = (int)$x['overrides'];
                $x['can_admin'] = nm_user_can($conn, $x['UID'], $x['role'], 'user_admin');
                $users[] = $x;
            }
            echo json_encode(['users'=>$users]);
            break;
        }

        // ── Read: effective permission map for one user (per-user modal) ─────
        case 'user_perms': {
            $uid = (int)($_GET['uid'] ?? 0);
            $ur = $conn->prepare("SELECT USERNAME, role FROM users WHERE UID=?");
            $ur->bind_param('i', $uid); $ur->execute();
            $u = $ur->get_result()->fetch_assoc(); $ur->close();
            if (!$u) { http_response_code(404); echo json_encode(['err'=>'No such user']); break; }

            // role defaults
            $roleMap = [];
            $st = $conn->prepare("SELECT button_key, enabled FROM role_profiles WHERE role_name=?");
            $st->bind_param('s', $u['role']); $st->execute();
            $r = $st->get_result(); while ($z=$r->fetch_assoc()) $roleMap[$z['button_key']] = (bool)$z['enabled']; $st->close();

            // overrides
            $ovr = [];
            $st = $conn->prepare("SELECT button_key, effect FROM nm_user_perms WHERE uid=?");
            $st->bind_param('i', $uid); $st->execute();
            $r = $st->get_result(); while ($z=$r->fetch_assoc()) $ovr[$z['button_key']] = $z['effect']; $st->close();

            $rows = [];
            foreach ($catalog_payload as $c) {
                $k = $c['key'];
                $rows[] = [
                    'key'=>$k, 'label'=>$c['label'], 'category'=>$c['category'], 'icon'=>$c['icon'],
                    'role_default'=> !empty($roleMap[$k]),
                    'override'    => $ovr[$k] ?? 'inherit',      // allow|deny|inherit
                    'effective'   => isset($ovr[$k]) ? ($ovr[$k]==='allow') : !empty($roleMap[$k]),
                ];
            }
            echo json_encode(['user'=>['uid'=>$uid,'username'=>$u['USERNAME'],'role'=>$u['role']],'rows'=>$rows]);
            break;
        }

        // ── Read: role permission matrix ─────────────────────────────────────
        case 'role_perms': {
            $role = $_GET['role'] ?? '';
            if (!$valid_role($role)) { http_response_code(400); echo json_encode(['err'=>'Bad role']); break; }
            $map = [];
            $st = $conn->prepare("SELECT button_key, enabled FROM role_profiles WHERE role_name=?");
            $st->bind_param('s', $role); $st->execute();
            $r = $st->get_result(); while ($z=$r->fetch_assoc()) $map[$z['button_key']] = (bool)$z['enabled']; $st->close();
            $rows = [];
            foreach ($catalog_payload as $c) {
                $rows[] = $c + ['enabled' => !empty($map[$c['key']])];
            }
            echo json_encode(['role'=>$role,'rows'=>$rows]);
            break;
        }

        // ── Write: create user ───────────────────────────────────────────────
        case 'user_create': {
            if (!$isPost) { http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $username = trim($_POST['username'] ?? '');
            $name     = trim($_POST['name'] ?? '');
            $email    = strtolower(trim($_POST['email'] ?? ''));
            $role     = trim($_POST['role'] ?? '');
            $pass     = (string)($_POST['password'] ?? '');
            if ($username==='' || $pass==='' || !$valid_role($role)) {
                echo json_encode(['err'=>'Username, password and a valid role are required']); break;
            }
            if (strlen($pass) < 6) { echo json_encode(['err'=>'Password must be at least 6 characters']); break; }
            // role must exist
            $rc = $conn->prepare("SELECT 1 FROM role_profiles WHERE role_name=? LIMIT 1");
            $rc->bind_param('s',$role); $rc->execute();
            if (!$rc->get_result()->fetch_row()) { $rc->close(); echo json_encode(['err'=>'Role does not exist']); break; }
            $rc->close();
            // unique username
            $uc = $conn->prepare("SELECT 1 FROM users WHERE USERNAME=? LIMIT 1");
            $uc->bind_param('s',$username); $uc->execute();
            if ($uc->get_result()->fetch_row()) { $uc->close(); echo json_encode(['err'=>'Username already exists']); break; }
            $uc->close();

            $hash = password_hash($pass, PASSWORD_DEFAULT);
            $ins = $conn->prepare("INSERT INTO users (USERNAME,name,PASSWORD,email,role) VALUES (?,?,?,?,?)");
            $ins->bind_param('sssss', $username, $name, $hash, $email, $role);
            $ins->execute();
            $newUid = $conn->insert_id;
            $ins->close();

            nm_audit($conn, 'user.create', ['target_type'=>'user','target_id'=>$newUid,
                'details'=>['username'=>$username,'role'=>$role,'email'=>$email]]);
            echo json_encode(['ok'=>true,'uid'=>$newUid]);
            break;
        }

        // ── Write: update user (name/email/role) ─────────────────────────────
        case 'user_update': {
            if (!$isPost) { http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $uid   = (int)($_POST['uid'] ?? 0);
            $name  = trim($_POST['name'] ?? '');
            $email = strtolower(trim($_POST['email'] ?? ''));
            $role  = trim($_POST['role'] ?? '');
            if ($uid<=0 || !$valid_role($role)) { echo json_encode(['err'=>'Bad input']); break; }
            $rc = $conn->prepare("SELECT 1 FROM role_profiles WHERE role_name=? LIMIT 1");
            $rc->bind_param('s',$role); $rc->execute();
            if (!$rc->get_result()->fetch_row()) { $rc->close(); echo json_encode(['err'=>'Role does not exist']); break; }
            $rc->close();

            $conn->begin_transaction();
            $up = $conn->prepare("UPDATE users SET name=?, email=?, role=? WHERE UID=?");
            $up->bind_param('sssi', $name, $email, $role, $uid);
            $up->execute(); $up->close();

            if (nm_access_admin_count($conn) < 1) {
                $conn->rollback();
                nm_audit($conn, 'user.update', ['status'=>'denied','target_type'=>'user','target_id'=>$uid,
                    'details'=>['blocked'=>'would_remove_last_admin','role'=>$role]]);
                echo json_encode(['err'=>'Blocked: this would leave no account able to manage Access Control']);
                break;
            }
            $conn->commit();
            // keep the acting admin's own session role fresh if they edited themselves
            if ($uid === $me_uid) $_SESSION['role'] = $role;
            nm_audit($conn, 'user.update', ['target_type'=>'user','target_id'=>$uid,
                'details'=>['name'=>$name,'email'=>$email,'role'=>$role]]);
            echo json_encode(['ok'=>true]);
            break;
        }

        // ── Write: reset password ────────────────────────────────────────────
        case 'user_password': {
            if (!$isPost) { http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $uid  = (int)($_POST['uid'] ?? 0);
            $pass = (string)($_POST['password'] ?? '');
            if ($uid<=0 || strlen($pass) < 6) { echo json_encode(['err'=>'Password must be at least 6 characters']); break; }
            $hash = password_hash($pass, PASSWORD_DEFAULT);
            $up = $conn->prepare("UPDATE users SET PASSWORD=? WHERE UID=?");
            $up->bind_param('si', $hash, $uid); $up->execute(); $up->close();
            nm_audit($conn, 'user.password_reset', ['target_type'=>'user','target_id'=>$uid]);
            echo json_encode(['ok'=>true]);
            break;
        }

        // ── Write: delete user ───────────────────────────────────────────────
        case 'user_delete': {
            if (!$isPost) { http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $uid = (int)($_POST['uid'] ?? 0);
            if ($uid<=0) { echo json_encode(['err'=>'Bad input']); break; }
            if ($uid === $me_uid) { echo json_encode(['err'=>"You can't delete your own account"]); break; }

            $conn->begin_transaction();
            $conn->query("DELETE FROM nm_user_perms WHERE uid=".$uid);
            $d = $conn->prepare("DELETE FROM users WHERE UID=?");
            $d->bind_param('i', $uid); $d->execute(); $d->close();

            if (nm_access_admin_count($conn) < 1) {
                $conn->rollback();
                echo json_encode(['err'=>'Blocked: this would leave no account able to manage Access Control']);
                break;
            }
            $conn->commit();
            nm_audit($conn, 'user.delete', ['target_type'=>'user','target_id'=>$uid]);
            echo json_encode(['ok'=>true]);
            break;
        }

        // ── Write: per-user permission override (allow|deny|inherit) ─────────
        case 'user_perm_save': {
            if (!$isPost) { http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $uid    = (int)($_POST['uid'] ?? 0);
            $key    = $_POST['key'] ?? '';
            $effect = $_POST['effect'] ?? '';   // allow | deny | inherit
            if ($uid<=0 || !$valid_key($key) || !in_array($effect,['allow','deny','inherit'],true)) {
                echo json_encode(['err'=>'Bad input']); break;
            }
            $conn->begin_transaction();
            if ($effect === 'inherit') {
                $d = $conn->prepare("DELETE FROM nm_user_perms WHERE uid=? AND button_key=?");
                $d->bind_param('is', $uid, $key); $d->execute(); $d->close();
            } else {
                $by = $_SESSION['username'] ?? '';
                $s = $conn->prepare("INSERT INTO nm_user_perms (uid,button_key,effect,updated_by) VALUES (?,?,?,?)
                                     ON DUPLICATE KEY UPDATE effect=VALUES(effect), updated_by=VALUES(updated_by)");
                $s->bind_param('isss', $uid, $key, $effect, $by); $s->execute(); $s->close();
            }
            if ($key==='user_admin' && nm_access_admin_count($conn) < 1) {
                $conn->rollback();
                echo json_encode(['err'=>'Blocked: this would leave no account able to manage Access Control']);
                break;
            }
            $conn->commit();
            nm_audit($conn, 'user.perm', ['target_type'=>'user','target_id'=>$uid,
                'details'=>['key'=>$key,'effect'=>$effect]]);
            echo json_encode(['ok'=>true]);
            break;
        }

        // ── Write: create role ───────────────────────────────────────────────
        case 'role_create': {
            if (!$isPost) { http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $role = trim($_POST['role'] ?? '');
            if (!$valid_role($role)) { echo json_encode(['err'=>'Role name: 2-20 chars, letters/numbers/_/- only']); break; }
            $rc = $conn->prepare("SELECT 1 FROM role_profiles WHERE role_name=? LIMIT 1");
            $rc->bind_param('s',$role); $rc->execute();
            if ($rc->get_result()->fetch_row()) { $rc->close(); echo json_encode(['err'=>'Role already exists']); break; }
            $rc->close();
            // seed every catalog key disabled
            $ins = $conn->prepare("INSERT INTO role_profiles (role_name,button_key,enabled) VALUES (?,?,0)");
            foreach ($allKeys as $k) { $ins->bind_param('ss',$role,$k); $ins->execute(); }
            $ins->close();
            nm_audit($conn, 'role.create', ['target_type'=>'role','target_id'=>$role]);
            echo json_encode(['ok'=>true]);
            break;
        }

        // ── Write: toggle one role permission ────────────────────────────────
        case 'role_perm_save': {
            if (!$isPost) { http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $role = trim($_POST['role'] ?? '');
            $key  = $_POST['key'] ?? '';
            $en   = (int)($_POST['enabled'] ?? 0) ? 1 : 0;
            if (!$valid_role($role) || !$valid_key($key)) { echo json_encode(['err'=>'Bad input']); break; }

            $conn->begin_transaction();
            // upsert (role row may pre-date a newly added key)
            $s = $conn->prepare("INSERT INTO role_profiles (role_name,button_key,enabled) VALUES (?,?,?)
                                 ON DUPLICATE KEY UPDATE enabled=VALUES(enabled)");
            $s->bind_param('ssi', $role, $key, $en); $s->execute(); $s->close();

            if ($key==='user_admin' && !$en && nm_access_admin_count($conn) < 1) {
                $conn->rollback();
                echo json_encode(['err'=>'Blocked: this would leave no account able to manage Access Control']);
                break;
            }
            $conn->commit();
            nm_audit($conn, 'role.perm', ['target_type'=>'role','target_id'=>$role,
                'details'=>['key'=>$key,'enabled'=>$en]]);
            echo json_encode(['ok'=>true]);
            break;
        }

        // ── Write: delete role ───────────────────────────────────────────────
        case 'role_delete': {
            if (!$isPost) { http_response_code(405); echo json_encode(['err'=>'POST only']); break; }
            $role = trim($_POST['role'] ?? '');
            if (!$valid_role($role)) { echo json_encode(['err'=>'Bad role']); break; }
            // refuse if any user still has this role
            $uc = $conn->prepare("SELECT COUNT(*) c FROM users WHERE role=?");
            $uc->bind_param('s',$role); $uc->execute();
            $inUse = (int)$uc->get_result()->fetch_assoc()['c']; $uc->close();
            if ($inUse > 0) { echo json_encode(['err'=>"Role is assigned to $inUse user(s) — reassign them first"]); break; }

            $conn->begin_transaction();
            $d = $conn->prepare("DELETE FROM role_profiles WHERE role_name=?");
            $d->bind_param('s',$role); $d->execute(); $d->close();
            if (nm_access_admin_count($conn) < 1) { $conn->rollback(); echo json_encode(['err'=>'Blocked: would remove last admin path']); break; }
            $conn->commit();
            nm_audit($conn, 'role.delete', ['target_type'=>'role','target_id'=>$role]);
            echo json_encode(['ok'=>true]);
            break;
        }

        // ── Read: recent activity feed ───────────────────────────────────────
        case 'activity': {
            $rows = [];
            $res = $conn->query("SELECT ts,username,role,action,target_type,target_id,status,ip
                                 FROM nm_audit_log ORDER BY id DESC LIMIT 60");
            while ($x = $res->fetch_assoc()) $rows[] = $x;
            echo json_encode(['rows'=>$rows]);
            break;
        }

        default:
            http_response_code(400);
            echo json_encode(['err'=>'Unknown action']);
        }
    } catch (\Throwable $e) {
        if ($conn->errno) { @$conn->rollback(); }
        http_response_code(500);
        echo json_encode(['err'=>'Server error: '.$e->getMessage()]);
    }
    exit;
}

// ── HTML page ────────────────────────────────────────────────────────────────
include('check.php');
if (!checkAccess($conn, 'user_admin')) {
    header('Location: /denied_access.php?page=user_admin');
    exit;
}
include('header.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Control | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#4da3ff;--up:#2ecc71;--down:#e74c3c;--warn:#f39c12;--mut:#8a909a;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#000;color:#fff;overflow-x:hidden;}
.wrap{max-width:1600px;margin:0 auto;padding:18px 22px 60px;}
.glass-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:18px;}
h2{margin:0 0 16px;font-size:15px;color:var(--accent);display:flex;align-items:center;gap:9px;}
.section-sub{color:var(--mut);font-size:12px;margin:-8px 0 16px;}
.btn{padding:8px 15px;border-radius:9px;border:1px solid var(--border);background:rgba(255,255,255,.05);color:#cfd3da;font-size:12.5px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:7px;transition:.18s;text-decoration:none;}
.btn:hover{border-color:var(--accent);color:#fff;}
.btn-primary{background:rgba(77,163,255,.15);border-color:var(--accent);color:var(--accent);}
.btn-primary:hover{background:var(--accent);color:#000;}
.btn-success{background:rgba(46,204,113,.15);border-color:var(--up);color:var(--up);}
.btn-success:hover{background:var(--up);color:#000;}
.btn-danger{background:rgba(231,76,60,.12);border-color:var(--down);color:var(--down);}
.btn-danger:hover{background:var(--down);color:#fff;}
.btn-sm{padding:5px 9px;font-size:11px;border-radius:7px;}
.form-input,.form-select{background:rgba(255,255,255,0.07);border:1px solid var(--border);color:#fff;padding:9px 13px;border-radius:8px;font-size:13px;outline:none;transition:.2s;width:100%;box-sizing:border-box;}
.form-select{background:rgba(20,30,50,0.95);}
.form-input:focus,.form-select:focus{border-color:var(--accent);}
.fld{display:flex;flex-direction:column;gap:5px;margin-bottom:12px;}
.fld label{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--mut);}
/* layout */
.split{display:grid;grid-template-columns:300px 1fr;gap:18px;align-items:start;}
@media(max-width:900px){.split{grid-template-columns:1fr;}}
/* tables */
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;color:var(--mut);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.6px;padding:9px 11px;border-bottom:1px solid var(--border);}
td{padding:9px 11px;border-bottom:1px solid rgba(255,255,255,.05);vertical-align:middle;}
tr:hover td{background:rgba(255,255,255,.025);}
.umeta{color:var(--mut);font-size:11px;}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:#aab;}
.tag{font-size:10px;padding:2px 9px;border-radius:6px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;display:inline-flex;align-items:center;gap:5px;}
.tag-role{background:rgba(77,163,255,.14);color:#7fc0ff;}
.tag-admin{background:rgba(243,156,18,.16);color:#f7b733;}
.tag-ovr{background:rgba(192,143,214,.18);color:#d4a6f0;}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;}
/* stat cards */
.stat-row{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:18px;}
.stat-card{background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:14px;padding:16px 18px;}
.stat-card .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--mut);}
.stat-card .val{font-size:30px;font-weight:800;margin-top:4px;}
/* toggle switch */
.sw{position:relative;display:inline-block;width:42px;height:23px;flex:none;}
.sw input{opacity:0;width:0;height:0;}
.sw .sl{position:absolute;cursor:pointer;inset:0;background:#3a3f4b;border-radius:23px;transition:.25s;}
.sw .sl::before{content:'';position:absolute;width:17px;height:17px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.25s;}
.sw input:checked+.sl{background:var(--up);}
.sw input:checked+.sl::before{transform:translateX(19px);}
/* permission matrix */
.perm-cat{margin-bottom:16px;}
.perm-cat-h{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#9fb6d0;margin:0 0 9px;display:flex;align-items:center;gap:8px;}
.perm-cat-h .ct{background:rgba(77,163,255,.14);color:#7fc0ff;border-radius:20px;padding:1px 8px;font-size:10px;}
.perm-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:9px;}
.perm-item{display:flex;align-items:center;gap:11px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:11px;padding:10px 13px;transition:.18s;}
.perm-item.on{border-color:rgba(46,204,113,.5);background:rgba(46,204,113,.06);}
.perm-item i.pi{width:16px;text-align:center;color:var(--accent);}
.perm-item .pl{flex:1;min-width:0;}
.perm-item .pl b{font-size:12.5px;font-weight:600;display:block;}
.perm-item .pl small{font-size:9.5px;color:var(--mut);font-family:ui-monospace,monospace;}
/* tri-state segmented (per-user) */
.tri{display:inline-flex;border:1px solid var(--border);border-radius:8px;overflow:hidden;flex:none;}
.tri button{background:transparent;border:none;color:var(--mut);padding:5px 10px;font-size:11px;font-weight:700;cursor:pointer;transition:.15s;}
.tri button.a-allow.on{background:var(--up);color:#000;}
.tri button.a-inherit.on{background:rgba(77,163,255,.6);color:#fff;}
.tri button.a-deny.on{background:var(--down);color:#fff;}
.tri button:hover{color:#fff;}
.inh-hint{font-size:9.5px;color:var(--mut);margin-top:3px;}
/* role list */
.role-pill{display:flex;align-items:center;justify-content:space-between;padding:11px 13px;border:1px solid var(--border);border-radius:11px;margin-bottom:8px;cursor:pointer;transition:.18s;background:rgba(255,255,255,.03);}
.role-pill:hover{border-color:var(--accent);}
.role-pill.sel{border-color:var(--accent);background:rgba(77,163,255,.1);}
.role-pill .rn{font-weight:700;font-size:13.5px;text-transform:capitalize;}
.role-pill .rc{font-size:10.5px;color:var(--mut);}
/* modal */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(4px);display:none;align-items:flex-start;justify-content:center;z-index:1000;padding:40px 16px;overflow-y:auto;}
.modal-bg.show{display:flex;}
.modal{background:#0d1119;border:1px solid var(--border);border-radius:16px;width:100%;max-width:680px;padding:22px 24px;box-shadow:0 24px 70px rgba(0,0,0,.6);}
.modal h3{margin:0 0 4px;font-size:16px;display:flex;align-items:center;gap:9px;}
.modal .mh-sub{color:var(--mut);font-size:12px;margin-bottom:16px;}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px;}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.search-box{position:relative;}
.search-box i{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--mut);font-size:12px;}
.search-box input{padding-left:32px;}
/* toast */
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(120%);background:#11151d;border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:10px;padding:12px 18px;font-size:13px;z-index:2000;transition:.3s;max-width:90vw;}
#toast.show{transform:translateX(-50%) translateY(0);}
#toast.ok{border-left-color:var(--up);} #toast.bad{border-left-color:var(--down);}
.act-feed{max-height:520px;overflow-y:auto;}
.act-row{display:flex;gap:12px;align-items:center;padding:8px 4px;border-bottom:1px solid rgba(255,255,255,.05);font-size:12px;}
.act-row .a-act{font-family:ui-monospace,monospace;color:#7fd1ff;font-size:11.5px;min-width:150px;}
.hidden{display:none!important;}
</style>
</head>
<body>
<div class="wrap">

<?php nm_page_header('Access', 'Control', 'Security &amp; Permissions', 'fa-solid fa-user-shield'); ?>

<?php
nm_module_tabs([
    ['icon'=>'fa-solid fa-users-gear','label'=>'Users','href'=>'#users','active'=>true],
    ['icon'=>'fa-solid fa-shield-halved','label'=>'Roles','href'=>'#roles','active'=>false],
    ['icon'=>'fa-solid fa-wave-square','label'=>'Activity','href'=>'#activity','active'=>false],
]);
?>

<!-- ════════════════════════════ USERS TAB ════════════════════════════ -->
<section id="tab-users">
  <div class="stat-row">
    <div class="stat-card"><div class="lbl">Total Users</div><div class="val" id="st-users">—</div></div>
    <div class="stat-card"><div class="lbl">Roles</div><div class="val" style="color:var(--accent)" id="st-roles">—</div></div>
    <div class="stat-card"><div class="lbl">Access-Control Admins</div><div class="val" style="color:var(--warn)" id="st-admins">—</div></div>
  </div>

  <div class="glass-card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px;">
      <h2 style="margin:0;"><i class="fa-solid fa-users"></i> Users</h2>
      <div style="display:flex;gap:10px;align-items:center;">
        <div class="search-box"><i class="fa-solid fa-magnifying-glass"></i>
          <input class="form-input" id="user-search" placeholder="Search users…" style="width:230px;" oninput="renderUsers()"></div>
        <button class="btn btn-primary" onclick="openUserModal()"><i class="fa-solid fa-user-plus"></i> Add User</button>
      </div>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead><tr>
          <th>UID</th><th>Username</th><th>Name</th><th>Email</th><th>Role</th>
          <th>Access</th><th>Last Login</th><th style="text-align:right;">Actions</th>
        </tr></thead>
        <tbody id="users-tbody"><tr><td colspan="8" style="text-align:center;color:var(--mut);padding:30px;">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>
</section>

<!-- ════════════════════════════ ROLES TAB ════════════════════════════ -->
<section id="tab-roles" class="hidden">
  <div class="split">
    <div class="glass-card">
      <h2><i class="fa-solid fa-shield-halved"></i> Roles</h2>
      <div id="role-list"></div>
      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px;">
        <div class="fld"><label>Create new role</label>
          <input class="form-input" id="new-role" placeholder="e.g. operator" maxlength="20"></div>
        <button class="btn btn-success" style="width:100%;justify-content:center;" onclick="createRole()">
          <i class="fa-solid fa-plus"></i> Create Role</button>
      </div>
    </div>

    <div class="glass-card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:6px;">
        <h2 style="margin:0;"><i class="fa-solid fa-table-list"></i> Permissions —
          <span id="role-title" style="color:#fff;text-transform:capitalize;">…</span></h2>
        <button class="btn btn-danger btn-sm" id="role-del-btn" onclick="deleteRole()"><i class="fa-solid fa-trash"></i> Delete role</button>
      </div>
      <div class="stat-row" style="grid-template-columns:repeat(3,1fr);margin:14px 0 18px;">
        <div class="stat-card"><div class="lbl">Total</div><div class="val" id="rp-total" style="font-size:24px;">—</div></div>
        <div class="stat-card"><div class="lbl">Granted</div><div class="val" id="rp-granted" style="font-size:24px;color:var(--up);">—</div></div>
        <div class="stat-card"><div class="lbl">Revoked</div><div class="val" id="rp-revoked" style="font-size:24px;color:var(--down);">—</div></div>
      </div>
      <div id="role-matrix"><div style="color:var(--mut);padding:20px;text-align:center;">Select a role…</div></div>
    </div>
  </div>
</section>

<!-- ════════════════════════════ ACTIVITY TAB ════════════════════════════ -->
<section id="tab-activity" class="hidden">
  <div class="glass-card">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:6px;">
      <h2 style="margin:0;"><i class="fa-solid fa-wave-square"></i> Recent Security Activity</h2>
      <div style="display:flex;gap:10px;">
        <button class="btn btn-sm" onclick="loadActivity()"><i class="fa-solid fa-rotate"></i> Refresh</button>
        <a class="btn btn-sm btn-primary" href="audit_log.php"><i class="fa-solid fa-clipboard-list"></i> Full Audit Log</a>
      </div>
    </div>
    <div class="section-sub">Last 60 events — logins, page views, access denials, permission changes. The full searchable log lives in Audit.</div>
    <div class="act-feed" id="act-feed"><div style="color:var(--mut);padding:20px;">Loading…</div></div>
  </div>
</section>

</div>

<!-- ── User add/edit modal ── -->
<div class="modal-bg" id="user-modal">
  <div class="modal">
    <h3><i class="fa-solid fa-user-pen"></i> <span id="um-title">Add User</span></h3>
    <div class="mh-sub" id="um-sub">Create a new portal account.</div>
    <input type="hidden" id="um-uid">
    <div class="row2">
      <div class="fld"><label>Username</label><input class="form-input" id="um-username" placeholder="jsmith"></div>
      <div class="fld"><label>Full name</label><input class="form-input" id="um-name" placeholder="John Smith"></div>
    </div>
    <div class="fld"><label>Email</label><input class="form-input" id="um-email" placeholder="user@example.com"></div>
    <div class="row2">
      <div class="fld"><label>Role</label><select class="form-select" id="um-role"></select></div>
      <div class="fld"><label id="um-pass-lbl">Password</label><input class="form-input" id="um-password" type="password" placeholder="min 6 chars"></div>
    </div>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal('user-modal')">Cancel</button>
      <button class="btn btn-success" id="um-save" onclick="saveUser()"><i class="fa-solid fa-check"></i> Save</button>
    </div>
  </div>
</div>

<!-- ── Password reset modal ── -->
<div class="modal-bg" id="pass-modal">
  <div class="modal" style="max-width:440px;">
    <h3><i class="fa-solid fa-key"></i> Reset Password</h3>
    <div class="mh-sub" id="pm-sub">—</div>
    <input type="hidden" id="pm-uid">
    <div class="fld"><label>New password</label><input class="form-input" id="pm-password" type="password" placeholder="min 6 chars"></div>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal('pass-modal')">Cancel</button>
      <button class="btn btn-success" onclick="savePassword()"><i class="fa-solid fa-check"></i> Set Password</button>
    </div>
  </div>
</div>

<!-- ── Per-user access modal ── -->
<div class="modal-bg" id="access-modal">
  <div class="modal">
    <h3><i class="fa-solid fa-user-lock"></i> Page Access — <span id="am-user" style="color:var(--accent);"></span></h3>
    <div class="mh-sub">Per-user overrides take priority over the role default. Leave on <b>Inherit</b> to follow the role
      (<span id="am-role"></span>). <span style="color:var(--up)">Allow</span> grants a page,
      <span style="color:var(--down)">Deny</span> blocks it — regardless of role.</div>
    <div id="am-body"><div style="color:var(--mut);padding:18px;">Loading…</div></div>
    <div class="modal-actions">
      <button class="btn btn-primary" onclick="closeModal('access-modal')"><i class="fa-solid fa-check"></i> Done</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
const CSRF = <?= json_encode($CSRF) ?>;
let BOOT = null, USERS = [], CURROLE = null;

function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function toast(msg, kind){const t=document.getElementById('toast');t.className=kind||'';t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);}
function closeModal(id){document.getElementById(id).classList.remove('show');}

async function api(action, data){
  const isPost = !!data;
  let url='access_admin.php?api='+action, opt={};
  if(isPost){
    const fd=new FormData(); fd.append('api',action); fd.append('csrf',CSRF);
    for(const k in data) fd.append(k,data[k]);
    opt={method:'POST',body:fd};
  } else if (data===undefined && action.includes('=')) { url='access_admin.php?api='+action; }
  const r=await fetch(url,opt);
  let j; try{ j=await r.json(); }catch(e){ j={err:'Bad response'}; }
  if(!r.ok || j.err){ toast(j.err||('HTTP '+r.status),'bad'); throw new Error(j.err||r.status); }
  return j;
}
function apiGet(action){ return fetch('access_admin.php?api='+action).then(r=>r.json()); }

// ── Tabs ──
document.querySelectorAll('.nm-tab').forEach(t=>{
  t.addEventListener('click', e=>{
    e.preventDefault();
    document.querySelectorAll('.nm-tab').forEach(x=>x.classList.remove('is-active'));
    t.classList.add('is-active');
    const id=t.getAttribute('href').slice(1);
    ['users','roles','activity'].forEach(s=>document.getElementById('tab-'+s).classList.toggle('hidden', s!==id));
    if(id==='activity') loadActivity();
  });
});

// ── Boot ──
async function boot(){
  BOOT = await api('bootstrap');
  document.getElementById('st-roles').textContent = BOOT.roles.length;
  document.getElementById('st-admins').textContent = BOOT.admin_count;
  // role select in user modal
  const rsel=document.getElementById('um-role');
  rsel.innerHTML = BOOT.roles.map(r=>`<option value="${esc(r.role)}">${esc(r.role)}</option>`).join('');
  renderRoleList();
  await loadUsers();
}

// ════════════ USERS ════════════
async function loadUsers(){
  const d = await api('users');
  USERS = d.users;
  document.getElementById('st-users').textContent = USERS.length;
  renderUsers();
}
function renderUsers(){
  const q=(document.getElementById('user-search').value||'').toLowerCase();
  const rows=USERS.filter(u=>!q || (u.USERNAME||'').toLowerCase().includes(q) || (u.name||'').toLowerCase().includes(q) || (u.email||'').toLowerCase().includes(q) || (u.role||'').toLowerCase().includes(q));
  const tb=document.getElementById('users-tbody');
  if(!rows.length){ tb.innerHTML='<tr><td colspan="8" style="text-align:center;color:var(--mut);padding:30px;">No users.</td></tr>'; return; }
  tb.innerHTML = rows.map(u=>{
    const adminTag = u.can_admin ? '<span class="tag tag-admin"><i class="fa-solid fa-user-shield"></i> Admin</span>' : '';
    const ovr = u.overrides>0 ? `<span class="tag tag-ovr" title="${u.overrides} per-user override(s)"><i class="fa-solid fa-sliders"></i> ${u.overrides}</span>` : '<span class="umeta">role</span>';
    const ll = u.last_login ? esc(u.last_login) : '<span class="umeta">never</span>';
    return `<tr>
      <td class="mono">${u.UID}</td>
      <td><b>${esc(u.USERNAME||'')}</b></td>
      <td>${esc(u.name||'')||'<span class="umeta">—</span>'}</td>
      <td class="umeta">${esc(u.email||'')||'—'}</td>
      <td><span class="tag tag-role">${esc(u.role||'')}</span> ${adminTag}</td>
      <td>${ovr}</td>
      <td class="mono">${ll}</td>
      <td style="text-align:right;white-space:nowrap;">
        <button class="btn btn-sm" title="Page access" onclick="openAccess(${u.UID})"><i class="fa-solid fa-user-lock"></i></button>
        <button class="btn btn-sm" title="Edit" onclick="openUserModal(${u.UID})"><i class="fa-solid fa-pen"></i></button>
        <button class="btn btn-sm" title="Reset password" onclick="openPass(${u.UID})"><i class="fa-solid fa-key"></i></button>
        <button class="btn btn-sm btn-danger" title="Delete" onclick="delUser(${u.UID})"><i class="fa-solid fa-trash"></i></button>
      </td></tr>`;
  }).join('');
}

function openUserModal(uid){
  const m=document.getElementById('user-modal');
  document.getElementById('um-uid').value = uid||'';
  if(uid){
    const u=USERS.find(x=>x.UID===uid);
    document.getElementById('um-title').textContent='Edit User';
    document.getElementById('um-sub').textContent='Update account details and role.';
    document.getElementById('um-username').value=u.USERNAME||'';
    document.getElementById('um-username').disabled=true;
    document.getElementById('um-name').value=u.name||'';
    document.getElementById('um-email').value=u.email||'';
    document.getElementById('um-role').value=u.role||'';
    document.getElementById('um-pass-lbl').textContent='Password (unchanged)';
    document.getElementById('um-password').value=''; document.getElementById('um-password').placeholder='Use “Reset password” to change';
    document.getElementById('um-password').disabled=true;
  } else {
    document.getElementById('um-title').textContent='Add User';
    document.getElementById('um-sub').textContent='Create a new portal account.';
    ['um-username','um-name','um-email','um-password'].forEach(id=>document.getElementById(id).value='');
    document.getElementById('um-username').disabled=false;
    document.getElementById('um-password').disabled=false;
    document.getElementById('um-pass-lbl').textContent='Password';
    document.getElementById('um-password').placeholder='min 6 chars';
    if(BOOT.roles.length) document.getElementById('um-role').value=BOOT.roles[0].role;
  }
  m.classList.add('show');
}
async function saveUser(){
  const uid=document.getElementById('um-uid').value;
  const data={
    name:document.getElementById('um-name').value.trim(),
    email:document.getElementById('um-email').value.trim(),
    role:document.getElementById('um-role').value,
  };
  if(uid){
    data.uid=uid;
    await api('user_update',data);
    toast('User updated','ok');
  } else {
    data.username=document.getElementById('um-username').value.trim();
    data.password=document.getElementById('um-password').value;
    await api('user_create',data);
    toast('User created','ok');
  }
  closeModal('user-modal');
  await boot();
}
function openPass(uid){
  const u=USERS.find(x=>x.UID===uid);
  document.getElementById('pm-uid').value=uid;
  document.getElementById('pm-password').value='';
  document.getElementById('pm-sub').innerHTML='Set a new password for <b>'+esc(u.USERNAME)+'</b>.';
  document.getElementById('pass-modal').classList.add('show');
}
async function savePassword(){
  const uid=document.getElementById('pm-uid').value;
  const pw=document.getElementById('pm-password').value;
  if(pw.length<6){ toast('Password must be at least 6 characters','bad'); return; }
  await api('user_password',{uid,password:pw});
  toast('Password updated','ok'); closeModal('pass-modal');
}
async function delUser(uid){
  const u=USERS.find(x=>x.UID===uid);
  if(!confirm('Delete user "'+(u.USERNAME)+'"? This also removes their access overrides. This cannot be undone.')) return;
  await api('user_delete',{uid});
  toast('User deleted','ok'); await boot();
}

// ── Per-user access modal ──
let AM_UID=null;
async function openAccess(uid){
  AM_UID=uid;
  const u=USERS.find(x=>x.UID===uid);
  document.getElementById('am-user').textContent=u.USERNAME;
  document.getElementById('access-modal').classList.add('show');
  document.getElementById('am-body').innerHTML='<div style="color:var(--mut);padding:18px;">Loading…</div>';
  const d=await api('user_perms&uid='+uid);
  document.getElementById('am-role').textContent=d.user.role;
  // group by category
  const cats={};
  d.rows.forEach(r=>{ (cats[r.category]=cats[r.category]||[]).push(r); });
  let html='';
  for(const cat in cats){
    html+=`<div class="perm-cat"><div class="perm-cat-h">${esc(cat)}</div><div style="display:flex;flex-direction:column;gap:8px;">`;
    cats[cat].forEach(r=>{
      const inhTxt = r.role_default ? 'allowed by role' : 'denied by role';
      html+=`<div class="perm-item ${r.effective?'on':''}" id="pi-${r.key}">
        <i class="${esc(r.icon)} pi"></i>
        <div class="pl"><b>${esc(r.label)}</b><small>${esc(r.key)}</small>
          <div class="inh-hint">Inherit = ${inhTxt}</div></div>
        <div class="tri" data-key="${esc(r.key)}">
          <button class="a-deny ${r.override==='deny'?'on':''}" onclick="setUserPerm('${r.key}','deny')">Deny</button>
          <button class="a-inherit ${r.override==='inherit'?'on':''}" onclick="setUserPerm('${r.key}','inherit')">Inherit</button>
          <button class="a-allow ${r.override==='allow'?'on':''}" onclick="setUserPerm('${r.key}','allow')">Allow</button>
        </div></div>`;
    });
    html+='</div></div>';
  }
  document.getElementById('am-body').innerHTML=html;
}
async function setUserPerm(key,effect){
  try{
    await api('user_perm_save',{uid:AM_UID,key,effect});
  }catch(e){ openAccess(AM_UID); return; }   // re-sync on a blocked change
  // update UI state
  const tri=document.querySelector(`.tri[data-key="${key}"]`);
  tri.querySelectorAll('button').forEach(b=>b.classList.remove('on'));
  tri.querySelector('.a-'+effect).classList.add('on');
  const row=BOOT && null;
  // recompute "on" highlight + effective
  const item=document.getElementById('pi-'+key);
  // we don't know role default here cheaply; just reflect explicit allow/deny, inherit needs role info → refetch lightweight
  if(effect==='allow') item.classList.add('on');
  else if(effect==='deny') item.classList.remove('on');
  else { /* inherit → refetch to show role default accurately */ const d=await api('user_perms&uid='+AM_UID); const rr=d.rows.find(x=>x.key===key); item.classList.toggle('on', rr.effective); }
  toast('Saved','ok');
  loadUsers(); // refresh override counts in the table
  refreshAdmins();
}

// ════════════ ROLES ════════════
function renderRoleList(){
  const el=document.getElementById('role-list');
  el.innerHTML = BOOT.roles.map(r=>`
    <div class="role-pill ${CURROLE===r.role?'sel':''}" onclick="selectRole('${esc(r.role)}')">
      <div><div class="rn">${esc(r.role)}</div><div class="rc">${r.granted}/${r.total} permissions</div></div>
      <i class="fa-solid fa-chevron-right" style="color:var(--mut);"></i>
    </div>`).join('');
  if(!CURROLE && BOOT.roles.length) selectRole(BOOT.roles[0].role);
}
async function selectRole(role){
  CURROLE=role;
  renderRoleList();
  document.getElementById('role-title').textContent=role;
  document.getElementById('role-matrix').innerHTML='<div style="color:var(--mut);padding:20px;text-align:center;">Loading…</div>';
  const d=await api('role_perms&role='+encodeURIComponent(role));
  const cats={}; d.rows.forEach(r=>{ (cats[r.category]=cats[r.category]||[]).push(r); });
  let granted=0;
  let html='';
  for(const cat in cats){
    const arr=cats[cat]; const gc=arr.filter(x=>x.enabled).length; granted+=gc;
    html+=`<div class="perm-cat"><div class="perm-cat-h">${esc(cat)} <span class="ct">${gc}/${arr.length}</span></div><div class="perm-grid">`;
    arr.forEach(r=>{
      html+=`<div class="perm-item ${r.enabled?'on':''}" id="rpi-${r.key}">
        <i class="${esc(r.icon)} pi"></i>
        <div class="pl"><b>${esc(r.label)}</b><small>${esc(r.key)}</small></div>
        <label class="sw"><input type="checkbox" ${r.enabled?'checked':''} onchange="toggleRolePerm('${esc(r.key)}',this)"><span class="sl"></span></label>
      </div>`;
    });
    html+='</div></div>';
  }
  document.getElementById('role-matrix').innerHTML=html;
  document.getElementById('rp-total').textContent=d.rows.length;
  document.getElementById('rp-granted').textContent=granted;
  document.getElementById('rp-revoked').textContent=d.rows.length-granted;
}
async function toggleRolePerm(key,el){
  const enabled=el.checked?1:0;
  try{
    await api('role_perm_save',{role:CURROLE,key,enabled});
  }catch(e){ el.checked=!el.checked; return; }
  document.getElementById('rpi-'+key).classList.toggle('on',el.checked);
  // refresh counts
  selectRoleCounts();
  // role granted count in BOOT + list
  const r=BOOT.roles.find(x=>x.role===CURROLE); if(r){ r.granted+=enabled?1:-1; }
  renderRoleList();
  refreshAdmins();
  toast('Saved','ok');
}
function selectRoleCounts(){
  const items=document.querySelectorAll('#role-matrix .sw input');
  let g=0; items.forEach(i=>{ if(i.checked) g++; });
  document.getElementById('rp-granted').textContent=g;
  document.getElementById('rp-revoked').textContent=items.length-g;
  // per-category chips
  document.querySelectorAll('#role-matrix .perm-cat').forEach(c=>{
    const boxes=c.querySelectorAll('.sw input'); const on=[...boxes].filter(b=>b.checked).length;
    const chip=c.querySelector('.ct'); if(chip) chip.textContent=on+'/'+boxes.length;
  });
}
async function createRole(){
  const name=document.getElementById('new-role').value.trim();
  if(!name){ toast('Enter a role name','bad'); return; }
  await api('role_create',{role:name});
  document.getElementById('new-role').value='';
  toast('Role created','ok');
  CURROLE=name; await boot(); selectRole(name);
  // ensure roles tab visible
}
async function deleteRole(){
  if(!CURROLE) return;
  if(!confirm('Delete role "'+CURROLE+'"? Only allowed if no users are assigned to it.')) return;
  try{ await api('role_delete',{role:CURROLE}); }catch(e){ return; }
  toast('Role deleted','ok'); CURROLE=null; await boot();
}

async function refreshAdmins(){
  try{ const d=await api('bootstrap'); BOOT.admin_count=d.admin_count; document.getElementById('st-admins').textContent=d.admin_count; }catch(e){}
}

// ════════════ ACTIVITY ════════════
async function loadActivity(){
  const d=await api('activity');
  const map={'ok':'var(--up)','denied':'var(--down)','failure':'var(--down)','error':'var(--warn)'};
  document.getElementById('act-feed').innerHTML = d.rows.map(r=>{
    const c=map[(r.status||'ok').toLowerCase()]||'var(--mut)';
    const tgt=[r.target_type,r.target_id].filter(Boolean).join(':');
    return `<div class="act-row">
      <span class="dot" style="background:${c}"></span>
      <span class="mono" style="min-width:140px;color:var(--mut)">${esc(r.ts)}</span>
      <span style="min-width:120px;">${esc(r.username||'—')} <span class="umeta">${esc(r.role||'')}</span></span>
      <span class="a-act">${esc(r.action)}</span>
      <span class="umeta" style="flex:1;">${esc(tgt)}</span>
      <span class="mono umeta">${esc(r.ip||'')}</span>
    </div>`;
  }).join('') || '<div style="color:var(--mut);padding:18px;">No activity.</div>';
}

// close modal on backdrop click
document.querySelectorAll('.modal-bg').forEach(m=>m.addEventListener('click',e=>{ if(e.target===m) m.classList.remove('show'); }));

boot();
</script>
</body>
</html>
