<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Admin Audit Log viewer. Reads nm_audit_log with filters + pagination.
// Admin-only (role_profiles button_key 'audit_log'). JSON API + HTML page.
// ─────────────────────────────────────────────────────────────────────────────

// ── Build the filtered WHERE clause shared by list + export ───────────────────
function audit_build_where(array $g): array {
    $where = []; $types = ''; $params = [];
    if (!empty($g['user']))   { $where[] = 'username = ?';   $types .= 's'; $params[] = $g['user']; }
    if (!empty($g['status'])) { $where[] = 'status = ?';     $types .= 's'; $params[] = $g['status']; }
    if (!empty($g['action'])) { $where[] = 'action = ?';     $types .= 's'; $params[] = $g['action']; }
    if (!empty($g['from']))   { $where[] = 'ts >= ?';        $types .= 's'; $params[] = $g['from'] . ' 00:00:00'; }
    if (!empty($g['to']))     { $where[] = 'ts <= ?';        $types .= 's'; $params[] = $g['to']   . ' 23:59:59'; }
    if (!empty($g['q'])) {
        $where[] = '(username LIKE ? OR action LIKE ? OR target_id LIKE ? OR uri LIKE ? OR details LIKE ? OR ip LIKE ?)';
        $like = '%' . $g['q'] . '%';
        for ($i = 0; $i < 6; $i++) { $types .= 's'; $params[] = $like; }
    }
    return ['sql' => $where ? ('WHERE ' . implode(' AND ', $where)) : '', 'types' => $types, 'params' => $params];
}

// ── AJAX API (must run before any output) ─────────────────────────────────────
if (isset($_GET['api'])) {
    if (session_status() === PHP_SESSION_NONE) session_start();
    include_once __DIR__ . '/connection.php';
    require_once __DIR__ . '/access_control.php';   // pulls nm_audit.php
    if (empty($_SESSION['username']) || !checkAccess($conn, 'audit_log')) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['err' => 'Unauthorized']);
        exit;
    }

    $g = [
        'q'      => trim($_GET['q']      ?? ''),
        'user'   => trim($_GET['user']   ?? ''),
        'action' => trim($_GET['action'] ?? ''),
        'status' => trim($_GET['status'] ?? ''),
        'from'   => preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['from'] ?? '') ? $_GET['from'] : '',
        'to'     => preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['to']   ?? '') ? $_GET['to']   : '',
    ];
    $w = audit_build_where($g);

    if ($_GET['api'] === 'export') {
        // CSV of all matching rows (capped)
        $sql = "SELECT ts,username,role,action,target_type,target_id,status,method,uri,ip,user_agent,details
                FROM nm_audit_log {$w['sql']} ORDER BY id DESC LIMIT 100000";
        $st = $conn->prepare($sql);
        if ($w['types']) $st->bind_param($w['types'], ...$w['params']);
        $st->execute();
        $res = $st->get_result();
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="netmon_audit_' . date('Ymd_His') . '.csv"');
        $out = fopen('php://output', 'w');
        fputcsv($out, ['Timestamp','User','Role','Action','Target Type','Target ID','Status','Method','URI','IP','User Agent','Details']);
        while ($r = $res->fetch_assoc()) fputcsv($out, $r);
        fclose($out);
        exit;
    }

    // api === 'list'
    header('Content-Type: application/json');
    $page = max(1, (int)($_GET['page'] ?? 1));
    $per  = min(200, max(10, (int)($_GET['per'] ?? 50)));
    $off  = ($page - 1) * $per;

    // total
    $cst = $conn->prepare("SELECT COUNT(*) c FROM nm_audit_log {$w['sql']}");
    if ($w['types']) $cst->bind_param($w['types'], ...$w['params']);
    $cst->execute();
    $total = (int)$cst->get_result()->fetch_assoc()['c'];

    // rows
    $sql = "SELECT id,ts,username,role,action,target_type,target_id,status,method,uri,ip,details
            FROM nm_audit_log {$w['sql']} ORDER BY id DESC LIMIT ? OFFSET ?";
    $st = $conn->prepare($sql);
    $types = $w['types'] . 'ii';
    $params = array_merge($w['params'], [$per, $off]);
    $st->bind_param($types, ...$params);
    $st->execute();
    $rows = $st->get_result()->fetch_all(MYSQLI_ASSOC);

    // distinct values for filter dropdowns
    $distinct = ['users' => [], 'actions' => [], 'statuses' => []];
    $dr = $conn->query("SELECT DISTINCT username FROM nm_audit_log WHERE username IS NOT NULL ORDER BY username LIMIT 200");
    while ($x = $dr->fetch_row()) $distinct['users'][] = $x[0];
    $dr = $conn->query("SELECT DISTINCT action FROM nm_audit_log ORDER BY action LIMIT 200");
    while ($x = $dr->fetch_row()) $distinct['actions'][] = $x[0];
    $dr = $conn->query("SELECT DISTINCT status FROM nm_audit_log ORDER BY status");
    while ($x = $dr->fetch_row()) $distinct['statuses'][] = $x[0];

    echo json_encode([
        'rows' => $rows, 'total' => $total, 'page' => $page, 'per' => $per,
        'pages' => max(1, (int)ceil($total / $per)), 'distinct' => $distinct,
    ]);
    exit;
}

// ── Page load ─────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
include('logger.php');

if (!checkAccess($conn, 'audit_log')) {
    header('Location: /denied_access.php?page=audit_log');
    exit;
}
include('header.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit Log | NetMon</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*,*::before,*::after { box-sizing:border-box; }
body { margin:0; background:#0f1117; color:#e6e8eb; font-family:'Segoe UI',Tahoma,sans-serif; }
.wrap { max-width:1400px; margin:0 auto; padding:18px 20px 40px; }
h1 { font-size:20px; margin:6px 0 4px; display:flex; align-items:center; gap:10px; }
h1 i { color:#4da3ff; }
.sub { color:#8a909a; font-size:12px; margin-bottom:16px; }
.card { background:#171a21; border:1px solid #262b36; border-radius:12px; padding:14px 16px; }
.filters { display:flex; flex-wrap:wrap; gap:10px; align-items:flex-end; margin-bottom:14px; }
.fld { display:flex; flex-direction:column; gap:4px; }
.fld label { font-size:10px; text-transform:uppercase; letter-spacing:.7px; color:#7c828c; }
.fld input, .fld select {
    background:#0f1117; border:1px solid #2b3140; color:#e6e8eb; border-radius:8px;
    padding:7px 10px; font-size:13px; outline:none; min-width:130px;
}
.fld input:focus, .fld select:focus { border-color:#4da3ff; }
.btn { background:rgba(77,163,255,.15); border:1px solid #4da3ff; color:#4da3ff; padding:8px 14px;
    border-radius:8px; font-size:13px; cursor:pointer; font-weight:600; display:inline-flex; align-items:center; gap:6px; }
.btn:hover { background:#4da3ff; color:#0f1117; }
.btn.ghost { background:transparent; border-color:#3a4150; color:#9aa0a6; }
.btn.ghost:hover { border-color:#8a909a; color:#e6e8eb; background:transparent; }
.stats { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; }
.stat { background:#171a21; border:1px solid #262b36; border-radius:10px; padding:8px 14px; font-size:12px; color:#9aa0a6; }
.stat b { color:#e6e8eb; font-size:16px; display:block; }
table { width:100%; border-collapse:collapse; font-size:12.5px; }
th { text-align:left; color:#7c828c; font-weight:600; font-size:10.5px; text-transform:uppercase; letter-spacing:.6px;
    padding:8px 10px; border-bottom:1px solid #262b36; position:sticky; top:0; background:#171a21; }
td { padding:7px 10px; border-bottom:1px solid #1d222b; vertical-align:top; }
tr:hover td { background:rgba(255,255,255,.02); }
.mono { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11.5px; color:#aab; }
.tag { font-size:10px; padding:1px 7px; border-radius:5px; font-weight:600; white-space:nowrap; }
.t-ok { background:rgba(46,204,113,.14); color:#2ecc71; }
.t-denied { background:rgba(231,76,60,.16); color:#e74c3c; }
.t-failure { background:rgba(231,76,60,.16); color:#e74c3c; }
.t-error { background:rgba(243,156,18,.16); color:#f39c12; }
.act { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11.5px; color:#7fd1ff; }
.details { max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#8a909a; }
.role { font-size:9.5px; color:#7c828c; text-transform:uppercase; }
.pager { display:flex; align-items:center; justify-content:space-between; margin-top:14px; gap:12px; flex-wrap:wrap; }
.pager .info { color:#8a909a; font-size:12px; }
.empty { text-align:center; color:#8a909a; padding:36px 0; }
</style>
</head>
<body>
<div class="wrap">
    <h1><i class="fa-solid fa-clipboard-list"></i> Audit Log</h1>
    <div class="sub">Every login, page view, access denial, and configuration change — searchable.</div>

    <div class="stats" id="stats"></div>

    <div class="card">
        <div class="filters">
            <div class="fld"><label>Search</label><input id="f-q" type="text" placeholder="user, action, IP, URI, details…"></div>
            <div class="fld"><label>User</label><select id="f-user"><option value="">All</option></select></div>
            <div class="fld"><label>Action</label><select id="f-action"><option value="">All</option></select></div>
            <div class="fld"><label>Status</label><select id="f-status"><option value="">All</option></select></div>
            <div class="fld"><label>From</label><input id="f-from" type="date"></div>
            <div class="fld"><label>To</label><input id="f-to" type="date"></div>
            <button class="btn" onclick="applyFilters()"><i class="fa-solid fa-magnifying-glass"></i> Apply</button>
            <button class="btn ghost" onclick="resetFilters()"><i class="fa-solid fa-rotate-left"></i> Reset</button>
            <button class="btn ghost" onclick="exportCsv()"><i class="fa-solid fa-file-csv"></i> Export CSV</button>
        </div>

        <div style="overflow-x:auto;">
        <table>
            <thead><tr>
                <th>Time</th><th>User</th><th>Action</th><th>Target</th>
                <th>Status</th><th>IP</th><th>Method</th><th>Details</th>
            </tr></thead>
            <tbody id="tbody"><tr><td colspan="8" class="empty">Loading…</td></tr></tbody>
        </table>
        </div>

        <div class="pager">
            <div class="info" id="pginfo"></div>
            <div>
                <button class="btn ghost" id="prev" onclick="go(-1)"><i class="fa-solid fa-chevron-left"></i> Prev</button>
                <button class="btn ghost" id="next" onclick="go(1)">Next <i class="fa-solid fa-chevron-right"></i></button>
            </div>
        </div>
    </div>
</div>

<script>
let _page = 1, _pages = 1, _filled = false;

function params() {
    const p = new URLSearchParams({
        q: document.getElementById('f-q').value.trim(),
        user: document.getElementById('f-user').value,
        action: document.getElementById('f-action').value,
        status: document.getElementById('f-status').value,
        from: document.getElementById('f-from').value,
        to: document.getElementById('f-to').value,
        page: _page, per: 50,
    });
    return p.toString();
}
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function fillSelect(id, vals, keep) {
    const el = document.getElementById(id);
    el.innerHTML = '<option value="">All</option>' + vals.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');
    if (keep) el.value = keep;
}

async function load() {
    document.getElementById('tbody').innerHTML = '<tr><td colspan="8" class="empty">Loading…</td></tr>';
    const r = await fetch('audit_log.php?api=list&' + params());
    if (!r.ok) { document.getElementById('tbody').innerHTML = '<tr><td colspan="8" class="empty">Access denied or error.</td></tr>'; return; }
    const d = await r.json();
    _pages = d.pages; _page = d.page;

    if (!_filled) {
        fillSelect('f-user', d.distinct.users);
        fillSelect('f-action', d.distinct.actions);
        fillSelect('f-status', d.distinct.statuses);
        _filled = true;
    }

    document.getElementById('stats').innerHTML =
        `<div class="stat"><b>${d.total.toLocaleString()}</b>matching events</div>
         <div class="stat"><b>${d.distinct.users.length}</b>users</div>
         <div class="stat"><b>${d.distinct.actions.length}</b>action types</div>`;

    if (!d.rows.length) {
        document.getElementById('tbody').innerHTML = '<tr><td colspan="8" class="empty">No events match these filters.</td></tr>';
    } else {
        document.getElementById('tbody').innerHTML = d.rows.map(row => {
            const st = (row.status||'ok').toLowerCase();
            const tgt = [row.target_type, row.target_id].filter(Boolean).join(':');
            return `<tr>
                <td class="mono">${esc(window.nmLocal ? nmLocal(row.ts,true) : row.ts)}</td>
                <td>${esc(row.username||'—')} <span class="role">${esc(row.role||'')}</span></td>
                <td class="act">${esc(row.action)}</td>
                <td class="mono">${esc(tgt||'—')}</td>
                <td><span class="tag t-${esc(st)}">${esc(st)}</span></td>
                <td class="mono">${esc(row.ip||'—')}</td>
                <td class="mono">${esc(row.method||'')}</td>
                <td class="details" title="${esc(row.uri||'')}\n${esc(row.details||'')}">${esc(row.details||row.uri||'—')}</td>
            </tr>`;
        }).join('');
    }

    document.getElementById('pginfo').textContent = `Page ${_page} of ${_pages} · ${d.total.toLocaleString()} events`;
    document.getElementById('prev').disabled = _page <= 1;
    document.getElementById('next').disabled = _page >= _pages;
}
function applyFilters(){ _page = 1; load(); }
function resetFilters(){
    ['f-q','f-user','f-action','f-status','f-from','f-to'].forEach(id=>document.getElementById(id).value='');
    _page = 1; load();
}
function go(d){ _page = Math.min(_pages, Math.max(1, _page + d)); load(); }
function exportCsv(){ window.location = 'audit_log.php?api=export&' + params(); }

document.getElementById('f-q').addEventListener('keydown', e=>{ if(e.key==='Enter') applyFilters(); });
load();
</script>
</body>
</html>
