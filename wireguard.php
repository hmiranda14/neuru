<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — WireGuard Universal Orchestrator UI. RBAC: 'wireguard'.
// Engine: nm_wireguard.php. Client-side QR via qrcode.js (cdnjs).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_wireguard.php');
require_once('nm_ipam.php');
include('logger.php');

$api = $_GET['api'] ?? '';
$act = $_POST['action'] ?? '';
if (!checkAccess($conn, 'wireguard')) {
    if ($api || $act) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=wireguard'); exit;
}
nm_wg_ensure($conn);
$uid = (int)($_SESSION['user_id'] ?? 0) ?: null;
// Release the session lock before any slow external I/O (SSH polls, GeoIP endpoint
// lookups on the peers list) so one WireGuard request can't freeze the user's portal.
if (function_exists('session_write_close')) @session_write_close();

if ($act !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($act === 'server_add')    { $r=nm_wg_server_add($conn,$_POST,$uid); log_user_action($conn,'wg_server_add',$_POST['name']??''); echo json_encode($r); exit; }
    if ($act === 'server_update') { echo json_encode(nm_wg_server_update($conn,(int)($_POST['id']??0),$_POST)); exit; }
    if ($act === 'server_delete') { echo json_encode(nm_wg_server_delete($conn,(int)($_POST['id']??0),!empty($_POST['wipe']),$uid)); exit; }
    if ($act === 'peer_add')      { $r=nm_wg_peer_add($conn,(int)($_POST['server_id']??0),$_POST,$uid);
        if (!empty($r['ok']) && !empty($r['id'])) {           // provision it on the device right away
            $ap = nm_wg_apply_peer($conn,(int)$r['id'],$uid);
            $r['applied']     = !empty($ap['ok']);
            $r['apply_error'] = !empty($ap['ok']) ? '' : (string)($ap['error'] ?? $ap['detail'] ?? 'apply failed');
        }
        log_user_action($conn,'wg_peer_add',$_POST['name']??''); echo json_encode($r); exit; }
    if ($act === 'peer_apply')    { echo json_encode(nm_wg_apply_peer($conn,(int)($_POST['id']??0),$uid)); exit; }
    if ($act === 'peer_delete')   { echo json_encode(nm_wg_peer_delete($conn,(int)($_POST['id']??0),!empty($_POST['wipe']),$uid)); exit; }
    if ($act === 'peer_wipe')      { echo json_encode(nm_wg_peer_remove_device($conn,(int)($_POST['id']??0),$uid)); exit; }
    if ($act === 'adopt')         { $r=nm_wg_adopt($conn,(int)($_POST['node_id']??0),$_POST,$uid); log_user_action($conn,'wg_adopt',($_POST['iface_name']??'').' on node '.($_POST['node_id']??'')); echo json_encode($r); exit; }
    if ($act === 'poll_stats')    { $sw=nm_wg_server($conn,(int)($_POST['server']??0)); echo json_encode($sw?nm_wg_poll_stats($conn,$sw):['ok'=>false,'error'=>'no server']); exit; }
    if ($act === 'apply')         { $r=nm_wg_apply($conn,(int)($_POST['server']??0),!empty($_POST['dry']),$uid); log_user_action($conn,'wg_apply',($_POST['server']??'').(!empty($_POST['dry'])?' dry':' LIVE')); echo json_encode($r); exit; }
    if ($act === 'revert')        { $r=nm_wg_revert($conn,(int)($_POST['server']??0),$uid); log_user_action($conn,'wg_revert',(string)($_POST['server']??'')); echo json_encode($r); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown action']); exit;
}

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($api === 'servers') { echo json_encode(['ok'=>true,'servers'=>nm_wg_servers($conn)]); exit; }
    if ($api === 'genkeys') { echo json_encode(['ok'=>true]+nm_wg_genkeys()); exit; }
    if ($api === 'peers')   { echo json_encode(['ok'=>true,'peers'=>nm_wg_peers($conn,(int)($_GET['server']??0))]); exit; }
    if ($api === 'render')  {
        $b = nm_wg_bundle($conn,(int)($_GET['server']??0));
        echo json_encode($b? ['ok'=>true]+nm_wg_render($b['server'],$b['peers']) : ['ok'=>false,'error'=>'not found']); exit;
    }
    if ($api === 'peer_conf') {
        $peer = nm_wg_peer($conn,(int)($_GET['id']??0),true);
        if (!$peer) { echo json_encode(['ok'=>false,'error'=>'peer not found']); exit; }
        $srv = nm_wg_server($conn,(int)$peer['server_id']);
        echo json_encode(['ok'=>true,'config'=>nm_wg_render_peer_conf($srv,$peer),'has_priv'=>($peer['private_key']??'')!=='']); exit;
    }
    if ($api === 'discover') { echo json_encode(nm_wg_discover($conn,(int)($_GET['node']??0))); exit; }
    if ($api === 'ptraffic') { echo json_encode(['ok'=>true,'points'=>nm_wg_peer_traffic($conn,(int)($_GET['peer']??0),1440)]); exit; }
    if ($api === 'logs')    { echo json_encode(['ok'=>true,'logs'=>nm_wg_logs($conn,(int)($_GET['server']??0))]); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn,'view_page','wireguard.php');
$subnets = nm_ipam_subnets($conn);
$nodes = [];
$nr = $conn->query("SELECT id,display_name,ip_address FROM nm_nodes ORDER BY display_name LIMIT 1000");
while ($nr && ($x=$nr->fetch_assoc())) $nodes[] = $x;
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WireGuard Orchestrator | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/qrcode.min.js"></script><!-- self-hosted: CSP script-src is 'self', cdnjs scripts are blocked -->
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; } .btn.sm{ padding:3px 9px; font-size:11px; }
.btn.warn{ background:rgba(243,156,18,.15); border-color:rgba(243,156,18,.45); color:#f0c674; }
.btn.danger{ color:#f0a59d; border-color:rgba(231,76,60,.4); }
.tabs{ display:flex; gap:8px; margin-bottom:16px; }
.tab{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aab; padding:9px 18px; border-radius:10px; cursor:pointer; font-size:13px; font-weight:600; }
.tab.active{ background:rgba(77,163,255,.15); border-color:var(--accent); color:var(--accent); }
.tp{ display:none; } .tp.active{ display:block; }
.srv{ display:grid; grid-template-columns:repeat(auto-fill,minmax(330px,1fr)); gap:14px; }
.s{ padding:14px 16px; cursor:pointer; } .s.active{ border-color:var(--accent); }
.s .nm{ font-size:15px; font-weight:800; } .s .meta{ font-size:11px; color:#8a909a; margin:4px 0; }
.tt{ display:inline-block; font-size:10px; font-weight:700; padding:2px 8px; border-radius:20px; background:rgba(77,163,255,.14); color:#bcd; }
.st{ font-size:11px; font-weight:700; } .st.applied{ color:var(--ok);} .st.error{ color:var(--crit);} .st.draft{ color:#8a909a;}
table{ width:100%; border-collapse:collapse; font-size:12.5px; }
th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:7px 9px; border-bottom:1px solid var(--border); }
td{ padding:7px 9px; border-bottom:1px solid rgba(255,255,255,.05); }
pre{ background:#0a0d12; border:1px solid var(--border); border-radius:10px; padding:14px; font-size:12px; overflow:auto; max-height:340px; white-space:pre-wrap; word-break:break-all; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
.modal-bg{ position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:90; display:none; align-items:flex-start; justify-content:center; padding-top:6vh; overflow:auto; }
.modal{ width:520px; max-width:95vw; padding:22px 24px; margin-bottom:40px; } .modal h3{ margin:0 0 14px; }
.modal label{ display:block; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin:10px 0 4px; }
.modal input,.modal select{ width:100%; background:rgba(255,255,255,.06); color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:9px 11px; font-size:13px; }
.row{ display:flex; gap:10px; } .row>div{ flex:1; }
.actions{ display:flex; gap:10px; justify-content:flex-end; margin-top:18px; align-items:center; }
#qrbox{ text-align:center; } #qrbox canvas,#qrbox img{ background:#fff; padding:10px; border-radius:10px; }
.hidefor{ display:none; }
/* dropdowns: native options were dark-on-dark — force readable, solid background */
select, .modal select, .bar select{ background:#1b2129 !important; color:#e6e9ee; }
option{ background:#1b2129; color:#e6e9ee; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-shield-halved"></i>WireGuard Orchestrator', '', 'Multi-vendor VPN', 'fa-solid fa-shield-halved',
    '<button class="refresh-btn" onclick="loadServers()"><i class="fas fa-rotate"></i> Refresh</button>'); ?>

<div class="tabs">
  <div class="tab active" data-t="servers" onclick="showTab('servers')"><i class="fas fa-server"></i> Servers</div>
  <div class="tab" data-t="peers" onclick="showTab('peers')"><i class="fas fa-users"></i> Peers</div>
  <div class="tab" data-t="apply" onclick="showTab('apply');loadRender()"><i class="fas fa-rocket"></i> Templates &amp; Apply</div>
  <div class="tab" data-t="guide" onclick="showTab('guide')"><i class="fas fa-graduation-cap"></i> Guide</div>
</div>

<div id="tp-servers" class="tp active">
  <div style="margin-bottom:14px;display:flex;gap:8px;flex-wrap:wrap;">
    <button class="btn" onclick="openScan()"><i class="fas fa-magnifying-glass"></i> Adopt from a monitored device</button>
    <button class="btn ghost" onclick="openServer()"><i class="fas fa-plus"></i> Create new (greenfield)</button>
  </div>
  <div class="glass card" style="padding:11px 16px;"><div class="muted"><i class="fas fa-circle-info"></i> <b>Adopt</b> scans a router you already monitor, finds its existing WireGuard interfaces, and lets you add peers to one — no need to know its private key. <b>Create new</b> builds a fresh tunnel from scratch.</div></div>
  <div class="srv" id="servers"><div class="muted">Loading…</div></div>
</div>

<div id="tp-peers" class="tp">
  <div class="glass card" id="peers-head"><span class="muted">Select a server in the Servers tab first.</span></div>
  <div id="peers-wrap" class="hidefor">
    <div style="margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
      <button class="btn" onclick="openPeer()"><i class="fas fa-plus"></i> Add peer</button>
      <button class="btn ghost" onclick="pollStats()"><i class="fas fa-satellite-dish"></i> Poll live stats</button>
      <span class="muted" id="peer-sub"></span><span class="muted" id="stat-msg"></span>
    </div>
    <div class="glass card" style="overflow-x:auto;"><table><thead><tr>
      <th>#</th><th>Name</th><th>Tunnel IP</th><th>Status</th><th>Last handshake</th><th>Traffic ↓ / ↑</th><th>Trend</th><th>Endpoint</th><th></th>
    </tr></thead><tbody id="peers-body"></tbody></table></div>
  </div>
</div>

<div id="tp-apply" class="tp">
  <div class="glass card" id="apply-head"><span class="muted">Select a server first.</span></div>
  <div id="apply-wrap" class="hidefor">
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <button class="btn ghost" onclick="loadRender()"><i class="fas fa-file-code"></i> Re-render</button>
      <button class="btn warn" onclick="doApply(true)"><i class="fas fa-eye"></i> Dry-run (preview commands)</button>
      <button class="btn" onclick="doApply(false)"><i class="fas fa-rocket"></i> Apply to device</button>
      <button class="btn ghost" onclick="copyCfg()"><i class="fas fa-copy"></i> Copy</button>
      <button class="btn danger" onclick="doRevert()" style="margin-left:auto;"><i class="fas fa-eraser"></i> Wipe from device</button>
    </div>
    <div class="muted" style="margin:-4px 0 10px;font-size:11.5px;"><i class="fas fa-circle-info"></i> <b>Apply</b> is idempotent — safe to run again. <b>Wipe from device</b> removes the interface, its address, the NEURU firewall rule, every NEURU route and all our peers (exactly what was provisioned — NEURU keeps the rollback commands in the Apply log). <span id="apply-msg"></span></div>
    <pre id="render"></pre>
    <h3 style="font-size:12px;color:var(--accent);text-transform:uppercase;letter-spacing:1px;margin:18px 0 8px;">Apply log</h3>
    <div class="glass card"><table><thead><tr><th>When</th><th>Action</th><th>Target</th><th>OK</th><th>Detail</th></tr></thead>
    <tbody id="logs-body"><tr><td colspan="5" class="muted">—</td></tr></tbody></table></div>
  </div>
</div>

<div id="tp-guide" class="tp">
  <div class="glass card" style="line-height:1.65;">
    <h2 style="margin:0 0 6px;font-size:20px;"><i class="fas fa-graduation-cap" style="color:var(--accent)"></i> WireGuard — how to build any topology</h2>
    <p class="muted" style="margin:0 0 4px;">Pick the scenario that matches what you need, then follow the numbered steps. NEURU does the dangerous parts for you: it opens the firewall <b>above</b> the drop rule (<span class="mono">place-before=0</span>), adds the <b>static routes</b> for site-to-site LANs, makes every apply <b>idempotent</b> (re-runnable), and <b>saves the exact rollback</b> so you can wipe cleanly.</p>
  </div>

  <div class="glass card">
    <h3 style="margin:0 0 8px;color:var(--accent);"><i class="fas fa-book"></i> The 7 words you need</h3>
    <table><tbody>
      <tr><td style="width:150px;"><b>Server</b></td><td>The “always-on” side that <b>listens</b> on a UDP port (your router with a public IP / DNS). In NEURU this is an entry on the <b>Servers</b> tab.</td></tr>
      <tr><td><b>Peer</b></td><td>Anything that <b>dials in</b> to a server — a phone, a laptop, or another router. Added on the <b>Peers</b> tab.</td></tr>
      <tr><td><b>Tunnel IP</b></td><td>The private address each side has <i>inside</i> the VPN (e.g. <span class="mono">10.51.0.1</span>). Not your LAN, not your WAN.</td></tr>
      <tr><td><b>Endpoint</b></td><td>The <b>public</b> WAN IP / DNS + port a peer dials to reach the server (e.g. <span class="mono">vpn.acme.net:51820</span>). Set it on the server (Edit → Public endpoint).</td></tr>
      <tr><td><b>AllowedIPs</b></td><td>Two jobs: (1) which traffic is <b>allowed</b> through, and (2) which networks <b>route</b> into the tunnel. <span class="mono">0.0.0.0/0</span> = send all traffic; a LAN like <span class="mono">192.168.10.0/24</span> = reach that office.</td></tr>
      <tr><td><b>Keepalive</b></td><td>Seconds between tiny “I’m alive” packets (25 is typical). Needed when a side is behind NAT so the tunnel stays open.</td></tr>
      <tr><td><b>PSK</b></td><td>Optional pre-shared key — an extra symmetric secret on top of the keypair. Tick the box when adding a peer for max hardening.</td></tr>
    </tbody></table>
  </div>

  <div class="glass card">
    <h3 style="margin:0 0 6px;color:var(--ok);"><i class="fas fa-mobile-screen"></i> Scenario A — Road-warrior &nbsp;<span class="muted" style="font-weight:400;">(phone / laptop → router)</span></h3>
    <p class="muted" style="margin:0 0 8px;">“I want my phone or laptop to reach the office/home network from anywhere.” One router = <b>server</b>, each device = a <b>peer</b> with a QR code.</p>
    <ol style="margin:0;padding-left:20px;">
      <li><b>Servers → Create new (greenfield)</b>. Pick the MikroTik node, interface <span class="mono">wg0</span>, listen port <span class="mono">51820</span>, tunnel address <span class="mono">10.8.0.1/24</span>.</li>
      <li>Set <b>Public endpoint</b> = your router’s WAN IP or DNS (e.g. <span class="mono">myrouter.sn.mynetname.net</span>). Optionally pick an IPAM subnet so peer IPs auto-allocate.</li>
      <li>(Optional) <b>Default AllowedIPs</b> = <span class="mono">0.0.0.0/0</span> to tunnel <i>all</i> phone traffic, or your LAN <span class="mono">192.168.88.0/24</span> to only reach the office.</li>
      <li><b>Templates &amp; Apply → Apply to device.</b> NEURU creates the interface, the address, and the firewall opening (above the drop).</li>
      <li><b>Peers → Add peer</b> (“phone-hector”). Leave Tunnel IP blank for auto. Save → a <b>QR code</b> appears. Scan it in the WireGuard mobile app. Done.</li>
    </ol>
    <p class="muted" style="margin:8px 0 0;"><i class="fas fa-lightbulb"></i> The peer is pushed to the router the instant you add it — no extra apply needed.</p>
  </div>

  <div class="glass card">
    <h3 style="margin:0 0 6px;color:var(--warn);"><i class="fas fa-arrows-left-right"></i> Scenario B — Site-to-site &nbsp;<span class="muted" style="font-weight:400;">(router ↔ router)</span></h3>
    <p class="muted" style="margin:0 0 8px;">“Connect two offices so their LANs talk to each other.” One router is the <b>server</b> (the one with a reachable public IP); the other is registered as a <b>peer</b> that also carries its LAN.</p>
    <div class="row" style="gap:14px;flex-wrap:wrap;">
      <div style="min-width:280px;">
        <div style="font-weight:700;color:#cfe4ff;margin-bottom:4px;">Router A — the server (HQ, public IP)</div>
        <ol style="margin:0;padding-left:20px;">
          <li><b>Create new</b> on Router A. Tunnel <span class="mono">10.51.0.1/24</span>, port <span class="mono">51821</span>, <b>Public endpoint</b> = HQ WAN/DNS.</li>
          <li><b>Apply to device.</b></li>
          <li><b>Add peer</b> “branch-B”. In <b>Extra AllowedIPs</b> put <b>Branch B’s LAN</b>, e.g. <span class="mono">192.168.10.0/24</span>. NEURU auto-adds the <span class="mono">/ip route</span> to reach it.</li>
          <li>Open the peer’s QR/config and copy <b>Router A’s public key + endpoint</b> for the next step.</li>
        </ol>
      </div>
      <div style="min-width:280px;">
        <div style="font-weight:700;color:#cfe4ff;margin-bottom:4px;">Router B — the branch</div>
        <ol style="margin:0;padding-left:20px;">
          <li>Either <b>adopt</b> Router B (if monitored) and add Router A as a peer, or configure B by hand from the copied config.</li>
          <li>On B, the peer = Router A with <b>AllowedIPs</b> = <span class="mono">10.51.0.0/24,192.168.1.0/24</span> (tunnel + HQ LAN) and the HQ <b>Endpoint</b>.</li>
          <li>B needs a route for HQ’s LAN via the tunnel — NEURU adds it from the peer’s Extra AllowedIPs.</li>
        </ol>
      </div>
    </div>
    <p class="muted" style="margin:10px 0 0;"><i class="fas fa-triangle-exclamation" style="color:var(--warn)"></i> The two tunnel IPs must differ (<span class="mono">.1</span> vs <span class="mono">.2</span>) and each side’s <b>Extra AllowedIPs</b> must list the <b>other</b> side’s LAN — that single field both permits and routes the remote network.</p>
  </div>

  <div class="glass card">
    <h3 style="margin:0 0 6px;color:#f0c674;"><i class="fas fa-circle-down"></i> Scenario C — Adopt an existing tunnel</h3>
    <p class="muted" style="margin:0 0 8px;">“My router already runs WireGuard — I just want to manage/add peers.” No private key needed.</p>
    <ol style="margin:0;padding-left:20px;">
      <li><b>Servers → Adopt from a monitored device</b>, pick the router, <b>Scan</b>.</li>
      <li>Adopt the interface (optionally import its existing peers, read-only).</li>
      <li><b>Peers → Add peer</b> as usual — NEURU pushes only the peers it manages, never touching the originals.</li>
    </ol>
  </div>

  <div class="glass card">
    <h3 style="margin:0 0 6px;color:var(--crit);"><i class="fas fa-eraser"></i> Removing &amp; rolling back</h3>
    <ul style="margin:0;padding-left:20px;">
      <li><b>One peer, off the device only:</b> the <span class="mono"><i class="fas fa-eraser"></i></span> button on a peer row (removes the peer + its route, keeps it in NEURU).</li>
      <li><b>One peer, completely:</b> the <span class="mono"><i class="fas fa-trash"></i></span> button → choose “also remove from the live device”.</li>
      <li><b>Whole interface:</b> <b>Templates &amp; Apply → Wipe from device</b> removes the interface, tunnel address, the NEURU firewall rule, every NEURU route and all our peers — and nothing else.</li>
      <li><b>Audit / manual rollback:</b> every Apply writes an <b>apply_cmd</b> (what was sent) and a <b>revert_cmd</b> (the exact inverse) into the <b>Apply log</b>. Hover any row to read the full command.</li>
    </ul>
    <p class="muted" style="margin:8px 0 0;">NEURU tags everything it creates with a <span class="mono">NEURU</span> comment, so a wipe only ever touches what NEURU added — your hand-made rules are safe.</p>
  </div>

  <div class="glass card">
    <h3 style="margin:0 0 6px;color:var(--accent);"><i class="fas fa-stethoscope"></i> Tunnel won’t come up? Quick checks</h3>
    <table><tbody>
      <tr><td style="width:230px;"><b>No handshake at all</b></td><td>Endpoint wrong/unreachable, or the WAN firewall blocks UDP <span class="mono">:port</span> upstream of the router. NEURU’s accept rule is placed first, but an ISP/CGNAT in front can still block it.</td></tr>
      <tr><td><b>Handshake OK, no LAN access</b></td><td>Missing route or AllowedIPs — make sure the remote LAN is in the peer’s <b>Extra AllowedIPs</b> (NEURU then adds the route). Also enable IP forwarding / NAT on the far side.</td></tr>
      <tr><td><b>Drops after ~2 min idle</b></td><td>Set <b>Keepalive</b> = 25 on the NAT’d side.</td></tr>
      <tr><td><b>“empty output from device”</b></td><td>SSH credential for the node isn’t resolving — set the node’s SSH cred (or a default) in Config Manager.</td></tr>
    </tbody></table>
  </div>
</div>
</div>

<!-- server modal -->
<div class="modal-bg" id="srvbg"><div class="glass modal">
  <h3>Add WireGuard server</h3>
  <label>Name</label><input id="sv-name" placeholder="HQ tunnel">
  <div class="row">
    <div><label>Target type</label><select id="sv-tt" onchange="ttChange()">
      <option value="mikrotik">MikroTik (RouterOS v7, SSH)</option>
      <option value="linux">Linux / VyOS (wg-quick, SSH)</option>
      <option value="docker">Docker (wg-easy via Portainer)</option></select></div>
    <div><label>Interface</label><input id="sv-if" value="wg0"></div>
  </div>
  <div class="row" id="sv-node-row">
    <div><label>Target node (SSH)</label><select id="sv-node"><option value="">— pick a node —</option>
      <?php foreach($nodes as $n): ?><option value="<?= (int)$n['id'] ?>"><?= htmlspecialchars($n['display_name']) ?> (<?= htmlspecialchars($n['ip_address']) ?>)</option><?php endforeach; ?></select></div>
    <div><label>…or host IP</label><input id="sv-host" placeholder="10.10.0.1"></div>
  </div>
  <div class="row hidefor" id="sv-docker-row">
    <div><label>Portainer endpoint id</label><input id="sv-peid" type="number" placeholder="1"></div>
    <div><label>Container name</label><input id="sv-cname" placeholder="wg-easy"></div>
  </div>
  <div class="row">
    <div><label>Listen port</label><input id="sv-port" type="number" value="51820"></div>
    <div><label>Tunnel address (CIDR)</label><input id="sv-addr" placeholder="10.8.0.1/24"></div>
  </div>
  <div class="row">
    <div><label>VPN subnet (IPAM — auto IPs)</label><select id="sv-sub"><option value="">— none (manual peer IPs) —</option>
      <?php foreach($subnets as $s): ?><option value="<?= (int)$s['id'] ?>"><?= htmlspecialchars($s['cidr']) ?><?= $s['kind']==='wireguard'?' ⭐':'' ?></option><?php endforeach; ?></select></div>
    <div><label>Public endpoint (for peers/QR)</label><input id="sv-ep" placeholder="vpn.example.com"></div>
  </div>
  <div class="row">
    <div><label>Peer DNS (optional)</label><input id="sv-dns" placeholder="1.1.1.1"></div>
    <div><label>Default AllowedIPs (peers)</label><input id="sv-dall" value="0.0.0.0/0"></div>
  </div>
  <p class="muted" style="margin-top:8px;">A server keypair is auto-generated (sodium). The private key is stored encrypted (AES-256-GCM).</p>
  <div class="actions"><span class="muted" id="sv-msg" style="margin-right:auto;"></span>
    <button class="btn ghost" onclick="closeM('srvbg')">Cancel</button><button class="btn" onclick="saveServer()">Create</button></div>
</div></div>

<!-- server EDIT modal (endpoint / port / DNS / AllowedIPs) -->
<div class="modal-bg" id="srveditbg"><div class="glass modal" style="width:460px;">
  <h3 id="se-title">Edit server</h3>
  <input type="hidden" id="se-id">
  <label>Public endpoint (for peers/QR) <span class="muted">— your WAN IP or DNS the clients dial</span></label>
  <input id="se-ep" placeholder="vpn.example.com or 203.0.113.5">
  <div class="row">
    <div><label>Listen port</label><input id="se-port" type="number" placeholder="51820"></div>
    <div><label>Peer DNS (optional)</label><input id="se-dns" placeholder="1.1.1.1"></div>
  </div>
  <label>Default AllowedIPs (peers)</label><input id="se-dall" value="0.0.0.0/0">
  <p class="muted" style="margin-top:8px;">Changing the endpoint updates every peer's QR/config (rendered live). No re-keying needed.</p>
  <div class="actions"><span class="muted" id="se-msg" style="margin-right:auto;"></span>
    <button class="btn ghost" onclick="closeM('srveditbg')">Cancel</button><button class="btn" onclick="saveServerEdit()">Save</button></div>
</div></div>

<!-- peer modal -->
<div class="modal-bg" id="peerbg"><div class="glass modal">
  <h3>Add peer</h3>
  <label>Name</label><input id="pr-name" placeholder="laptop-hector">
  <div class="row">
    <div><label>Tunnel IP <span class="muted" id="pr-iphint"></span></label><input id="pr-ip" placeholder="(auto from IPAM)"></div>
    <div><label>Keepalive (s)</label><input id="pr-keep" type="number" value="25"></div>
  </div>
  <label>Extra AllowedIPs routed to this peer (optional)</label><input id="pr-allowed" placeholder="192.168.88.0/24">
  <label style="display:flex;gap:8px;align-items:center;margin-top:12px;"><input type="checkbox" id="pr-psk" style="width:auto;"> Use a pre-shared key (extra hardening)</label>
  <p class="muted" style="margin-top:8px;">A peer keypair is generated by the portal so we can show you the QR. The private key never leaves this page once you close it.</p>
  <div class="actions"><span class="muted" id="pr-msg" style="margin-right:auto;"></span>
    <button class="btn ghost" onclick="closeM('peerbg')">Cancel</button><button class="btn" onclick="savePeer()">Add &amp; allocate IP</button></div>
</div></div>

<!-- scan/adopt modal -->
<div class="modal-bg" id="scanbg"><div class="glass modal" style="width:600px;">
  <h3><i class="fas fa-magnifying-glass"></i> Adopt existing WireGuard</h3>
  <div class="row" style="align-items:flex-end;">
    <div><label>Monitored device (router / linux with SSH)</label><select id="sc-node">
      <option value="">— pick a device —</option>
      <?php foreach($nodes as $n): ?><option value="<?= (int)$n['id'] ?>"><?= htmlspecialchars($n['display_name']) ?> (<?= htmlspecialchars($n['ip_address']) ?>)</option><?php endforeach; ?>
    </select></div>
    <div style="flex:0 0 auto;"><button class="btn" onclick="runScan()"><i class="fas fa-satellite-dish"></i> Scan</button></div>
  </div>
  <div id="sc-result" style="margin-top:14px;"><span class="muted">Pick a device and Scan — NEURU will SSH in and read its WireGuard config.</span></div>
  <div class="actions"><button class="btn ghost" onclick="closeM('scanbg')">Close</button></div>
</div></div>

<!-- QR modal -->
<div class="modal-bg" id="qrbg"><div class="glass modal" style="width:420px;">
  <h3 id="qr-title">Peer config</h3>
  <div id="qr-applywarn" style="color:var(--warn);font-size:12px;margin-bottom:8px;line-height:1.5;"></div>
  <div id="qrbox"></div>
  <p class="muted" style="text-align:center;margin:12px 0 4px;">Scan with the WireGuard mobile app, or copy the config below.</p>
  <pre id="qr-text" style="max-height:200px;"></pre>
  <div class="actions"><button class="btn ghost" onclick="copyQR()"><i class="fas fa-copy"></i> Copy</button><button class="btn" onclick="closeM('qrbg')">Done</button></div>
</div></div>

<script>
let SRV=[], SEL=0, SELT='mikrotik', CFG='';
const WG_SUBNETS = <?= json_encode(array_map(fn($s)=>['id'=>(int)$s['id'],'cidr'=>$s['cidr'],'kind'=>$s['kind']], $subnets)) ?>;
function subnetOpts(){ return '<option value="">— none —</option>'+WG_SUBNETS.map(s=>`<option value="${s.id}">${esc(s.cidr)}${s.kind=='wireguard'?' ⭐':''}</option>`).join(''); }
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function gv(id){ return document.getElementById(id).value; }
function closeM(id){ document.getElementById(id).style.display='none'; }
function showTab(t){ document.querySelectorAll('.tp').forEach(p=>p.classList.remove('active')); document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
  document.getElementById('tp-'+t).classList.add('active'); document.querySelector('.tab[data-t="'+t+'"]').classList.add('active');
  if(t==='peers') loadPeers(); }
async function post(body){ return fetch('wireguard.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}).then(r=>r.json()).catch(()=>null); }

async function loadServers(){
  const r=await fetch('wireguard.php?api=servers').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok)return; SRV=r.servers;
  document.getElementById('servers').innerHTML = SRV.length? SRV.map(s=>`
    <div class="glass s ${s.id==SEL?'active':''}" onclick="selServer(${s.id})">
      <div class="nm">${esc(s.name)} <span class="tt">${esc(s.target_type)}</span>${s.adopted==1?' <span class="tt" style="background:rgba(243,156,18,.18);color:#f0c674;">adopted</span>':''}</div>
      <div class="meta">addr ${esc(s.address_cidr||'(from device)')} · :${s.listen_port} · ${s.peer_count} peer(s)</div>
      <div class="meta mono" style="font-size:10px;">pub ${esc((s.public_key||'').slice(0,28))}…</div>
      <div class="st ${esc(s.status)}">● ${esc(s.status)}${s.last_error?' — '+esc(s.last_error):''}</div>
      <div style="margin-top:8px;"><button class="btn ghost sm" onclick="event.stopPropagation();editServer(${s.id})"><i class="fas fa-pen"></i> edit</button> <button class="btn ghost sm" onclick="event.stopPropagation();delServer(${s.id})">delete</button></div>
    </div>`).join('') : '<div class="muted">No servers yet — add one.</div>';
}
function editServer(id){ const s=SRV.find(x=>x.id==id); if(!s)return;
  document.getElementById('se-id').value=id;
  document.getElementById('se-title').textContent='Edit: '+s.name;
  document.getElementById('se-ep').value=s.endpoint_host||'';
  document.getElementById('se-port').value=s.listen_port||51820;
  document.getElementById('se-dns').value=s.dns_servers||'';
  document.getElementById('se-dall').value=s.default_allowed||'0.0.0.0/0';
  document.getElementById('se-msg').textContent='';
  document.getElementById('srveditbg').style.display='flex';
}
async function saveServerEdit(){
  const b=new URLSearchParams({action:'server_update',id:gv('se-id'),endpoint_host:gv('se-ep'),listen_port:gv('se-port'),dns_servers:gv('se-dns'),default_allowed:gv('se-dall')});
  const r=await post(b);
  if(r&&r.ok){ closeM('srveditbg'); loadServers(); document.getElementById('se-msg').textContent=''; }
  else document.getElementById('se-msg').innerHTML='<span style="color:var(--crit)">'+(r?esc(r.error):'failed')+'</span>';
}
function selServer(id){ SEL=id; const s=SRV.find(x=>x.id==id); SELT=s?s.target_type:''; loadServers(); }
function ttChange(){ const tt=gv('sv-tt'); document.getElementById('sv-docker-row').classList.toggle('hidefor',tt!=='docker'); document.getElementById('sv-node-row').classList.toggle('hidefor',tt==='docker'); }
function openServer(){ ['sv-name','sv-host','sv-addr','sv-ep','sv-dns','sv-peid','sv-cname'].forEach(i=>document.getElementById(i).value=''); document.getElementById('sv-if').value='wg0'; document.getElementById('sv-port').value=51820; document.getElementById('sv-dall').value='0.0.0.0/0'; document.getElementById('sv-msg').textContent=''; ttChange(); document.getElementById('srvbg').style.display='flex'; }
async function saveServer(){
  const b=new URLSearchParams({action:'server_add',name:gv('sv-name'),target_type:gv('sv-tt'),iface_name:gv('sv-if'),
    node_id:gv('sv-node'),host_ip:gv('sv-host'),portainer_endpoint_id:gv('sv-peid'),container_name:gv('sv-cname'),
    listen_port:gv('sv-port'),address_cidr:gv('sv-addr'),vpn_subnet_id:gv('sv-sub'),endpoint_host:gv('sv-ep'),dns_servers:gv('sv-dns'),default_allowed:gv('sv-dall')});
  const r=await post(b); if(r&&r.ok){ closeM('srvbg'); SEL=r.id; loadServers(); } else document.getElementById('sv-msg').innerHTML='<span style="color:var(--crit)">'+(r?esc(r.error):'failed')+'</span>';
}
async function delServer(id){
  if(!confirm('Delete this server, its peers, and their IP reservations from NEURU?'))return;
  // offer to also wipe it off the live router (interface + firewall + routes + peers)
  const wipe = confirm('Also WIPE it from the live device now?\n\nOK = remove the WireGuard interface, NEURU firewall rule, routes and peers from the router, then delete here.\nCancel = only delete from NEURU (leave the device as-is).');
  const b=new URLSearchParams({action:'server_delete',id:id}); if(wipe) b.set('wipe','1');
  const r=await post(b);
  if(wipe && r && r.wiped===false) alert('Deleted from NEURU, but the device wipe failed: '+esc(r.wipe_error||'unknown')+'\nRemove it on the router manually.');
  if(SEL==id)SEL=0; loadServers();
}

async function loadPeers(){
  const head=document.getElementById('peers-head'), wrap=document.getElementById('peers-wrap');
  if(!SEL){ head.innerHTML='<span class="muted">Select a server in the Servers tab first.</span>'; wrap.classList.add('hidefor'); return; }
  const s=SRV.find(x=>x.id==SEL);
  head.innerHTML=`<b>${esc(s.name)}</b> <span class="tt">${esc(s.target_type)}</span> — ${esc(s.address_cidr)}`;
  wrap.classList.remove('hidefor');
  document.getElementById('peer-sub').textContent = s.vpn_subnet_id? 'IPs auto-allocated from the linked IPAM subnet.' : 'No IPAM subnet — set peer IPs manually.';
  const r=await fetch('wireguard.php?api=peers&server='+SEL).then(r=>r.json()).catch(()=>null);
  const peers=r&&r.peers||[];
  const online=peers.filter(p=>p.connected==1).length;
  document.getElementById('peer-sub').innerHTML = (s.vpn_subnet_id?'IPs auto-allocated from IPAM. ':'')+`<b style="color:var(--ok)">${online}</b>/${peers.length} online`;
  document.getElementById('peers-body').innerHTML = peers.length? peers.map((p,i)=>{
    const on=p.connected==1;
    const stat = on?'<span style="color:var(--ok)">● online</span>':'<span style="color:#7c828c">○ offline</span>';
    return `<tr>
    <td>${i+1}</td><td>${esc(p.name)}${p.origin=='imported'?' <span class="tt" style="font-size:9px;">imported</span>':''}</td>
    <td class="mono">${esc(p.address_ip)}</td>
    <td>${stat}</td>
    <td class="muted">${relAge(p.hs_ago)}</td>
    <td class="mono" style="font-size:11px;">${fmtBytes(p.rx_bytes)} / ${fmtBytes(p.tx_bytes)}</td>
    <td><span id="pt-${p.id}"></span></td>
    <td class="mono muted" style="font-size:10px;">${p.endpoint_flag?`<span title="${esc(p.endpoint_country)}" style="font-size:12px;">${p.endpoint_flag}</span> `:(p.endpoint_private?'<span class="tt" style="font-size:8.5px;">LAN</span> ':'')}${esc(p.endpoint||'')}</td>
    <td style="white-space:nowrap;">${p.has_priv==1?`<button class="btn ghost sm" title="QR / config" onclick="showQR(${p.id},'${esc(p.name)}')"><i class="fas fa-qrcode"></i></button>`:''}
      <button class="btn ghost sm" title="Remove from device only" onclick="wipePeer(${p.id},'${esc(p.name)}')"><i class="fas fa-eraser"></i></button>
      <button class="btn ghost sm danger" title="Delete" onclick="delPeer(${p.id})"><i class="fas fa-trash"></i></button></td></tr>`;
  }).join('') : '<tr><td colspan="9" class="muted">No peers yet.</td></tr>';
  peers.forEach(p=>{ if(p.stats_at) drawPeerSpark(p.id); });
}
function fmtBytes(b){ b=+b||0; const u=['B','K','M','G','T']; let i=0; while(b>=1024&&i<4){b/=1024;i++;} return b.toFixed(i?1:0)+u[i]; }
function relAge(s){ if(s==null) return 'never'; s=+s; if(s<60)return s+'s ago'; if(s<3600)return Math.floor(s/60)+'m ago'; if(s<86400)return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }
async function pollStats(){
  const m=document.getElementById('stat-msg'); m.style.color='#9aa'; m.innerHTML='<i class="fas fa-spinner fa-spin"></i> Polling device…';
  const r=await post(new URLSearchParams({action:'poll_stats',server:SEL}));
  if(r&&r.ok){ m.style.color='var(--ok)'; m.textContent='✓ Updated '+r.peers+' peer(s) ('+r.seen+' on device)'; loadPeers(); }
  else { m.style.color='var(--crit)'; m.textContent='✗ '+(r?esc(r.error):'failed'); }
}
async function drawPeerSpark(id){
  const el=document.getElementById('pt-'+id); if(!el) return;
  const r=await fetch('wireguard.php?api=ptraffic&peer='+id).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok||r.points.length<2){ el.innerHTML='<span class="muted" style="font-size:10px;">—</span>'; return; }
  const w=90,h=20,rx=r.points.map(p=>p.rx),tx=r.points.map(p=>p.tx),mx=Math.max(1,...rx,...tx);
  const line=(a,c)=>{const pts=a.map((v,i)=>`${(i/(a.length-1))*w},${h-(v/mx)*(h-2)-1}`).join(' ');return `<polyline points="${pts}" fill="none" stroke="${c}" stroke-width="1.2"/>`;};
  el.innerHTML=`<svg width="${w}" height="${h}">${line(rx,'#2ecc71')}${line(tx,'#4da3ff')}</svg>`;
}
function openPeer(){ if(!SEL){alert('Select a server first');return;} ['pr-name','pr-ip','pr-allowed'].forEach(i=>document.getElementById(i).value=''); document.getElementById('pr-keep').value=25; document.getElementById('pr-psk').checked=false; document.getElementById('pr-msg').textContent='';
  const s=SRV.find(x=>x.id==SEL); document.getElementById('pr-iphint').textContent=s&&s.vpn_subnet_id?'(blank = auto)':'(required)'; document.getElementById('peerbg').style.display='flex'; }
async function savePeer(){
  const b=new URLSearchParams({action:'peer_add',server_id:SEL,name:gv('pr-name'),address_ip:gv('pr-ip'),keepalive:gv('pr-keep'),allowed_ips:gv('pr-allowed')});
  if(document.getElementById('pr-psk').checked) b.set('use_psk','1');
  const r=await post(b);
  if(r&&r.ok){ closeM('peerbg'); loadPeers(); loadServers(); setTimeout(()=>showQR(r.id,gv('pr-name'), r.applied===false?(r.apply_error||'could not reach the router'):''),200); }
  else document.getElementById('pr-msg').innerHTML='<span style="color:var(--crit)">'+(r?esc(r.error):'failed')+'</span>';
}
async function delPeer(id){
  if(!confirm('Delete this peer and release its IP?'))return;
  const wipe = confirm('Also remove it from the live device now?\n\nOK = delete the peer (and its NEURU route) off the router, then remove here.\nCancel = only remove from NEURU.');
  const b=new URLSearchParams({action:'peer_delete',id:id}); if(wipe) b.set('wipe','1');
  const r=await post(b);
  if(wipe && r && r.wiped===false) alert('Removed from NEURU, but the device removal failed: '+esc(r.wipe_error||'unknown'));
  loadPeers(); loadServers();
}
async function wipePeer(id,name){
  if(!confirm('Remove peer “'+name+'” from the live device (keep it in NEURU)?'))return;
  const r=await post(new URLSearchParams({action:'peer_wipe',id:id}));
  alert(r&&r.ok?'✓ Removed from device.':'✗ '+(r?esc(r.error||r.detail):'failed'));
  loadPeers();
}

async function showQR(id,name,applyWarn){
  const r=await fetch('wireguard.php?api=peer_conf&id='+id).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ alert(r?r.error:'failed'); return; }
  document.getElementById('qr-title').textContent='Peer: '+name;
  document.getElementById('qr-text').textContent=r.config;
  const box=document.getElementById('qrbox'); box.innerHTML='';
  if(typeof QRCode==='undefined'){ box.innerHTML='<div style="color:var(--warn);font-size:12px;padding:20px;">QR library not loaded. The config text below still works — paste it into the WireGuard app.</div>'; }
  else { new QRCode(box,{text:r.config,width:240,height:240,correctLevel:QRCode.CorrectLevel.M}); }
  // surface a clear notice if the peer was saved but not pushed to the router
  const warnEl=document.getElementById('qr-applywarn');
  if(warnEl) warnEl.innerHTML = applyWarn
    ? '<i class="fas fa-triangle-exclamation"></i> Saved, but NOT applied to the router: '+esc(applyWarn)+'. Use “Apply server” / re-add once SSH is reachable.'
    : '';
  document.getElementById('qrbg').style.display='flex';
}
function copyQR(){ navigator.clipboard.writeText(document.getElementById('qr-text').textContent); }
function copyCfg(){ navigator.clipboard.writeText(CFG); document.getElementById('apply-msg').textContent='Copied.'; }

async function loadRender(){
  const head=document.getElementById('apply-head'), wrap=document.getElementById('apply-wrap');
  if(!SEL){ head.innerHTML='<span class="muted">Select a server first.</span>'; wrap.classList.add('hidefor'); return; }
  const s=SRV.find(x=>x.id==SEL); head.innerHTML=`<b>${esc(s.name)}</b> <span class="tt">${esc(s.target_type)}</span> — rendered provisioning config`;
  wrap.classList.remove('hidefor');
  const r=await fetch('wireguard.php?api=render&server='+SEL).then(r=>r.json()).catch(()=>null);
  CFG = r&&r.ok? r.config : '(render failed)';
  document.getElementById('render').textContent = CFG;
  loadLogs();
}
async function doApply(dry){
  if(!dry && !confirm('Apply this WireGuard config to the live device now?'))return;
  document.getElementById('apply-msg').textContent = dry?'Rendering dry-run…':'Applying…';
  const r=await post(new URLSearchParams({action:'apply',server:SEL,dry:dry?'1':''}));
  if(r&&r.ok){
    if(dry){ document.getElementById('render').textContent=r.command; document.getElementById('apply-msg').innerHTML='<span style="color:var(--warn)">Dry-run — commands above were NOT sent.</span>'; }
    else { document.getElementById('apply-msg').innerHTML='<span style="color:var(--ok)">✓ Applied.</span>'; loadServers(); }
  } else document.getElementById('apply-msg').innerHTML='<span style="color:var(--crit)">✗ '+(r?esc(r.error||r.detail):'failed')+'</span>';
  loadLogs();
}
async function doRevert(){
  if(!SEL){alert('Select a server first');return;}
  const s=SRV.find(x=>x.id==SEL);
  if(!confirm('WIPE “'+(s?s.name:'')+'” from the live device?\n\nThis removes the WireGuard interface, its tunnel address, the NEURU firewall accept rule, every NEURU static route and all peers NEURU manages on it.\n\nThe rollback commands are saved in the Apply log. Continue?'))return;
  document.getElementById('apply-msg').innerHTML='<span style="color:var(--warn)">Wiping…</span>';
  const r=await post(new URLSearchParams({action:'revert',server:SEL}));
  if(r&&r.ok) document.getElementById('apply-msg').innerHTML='<span style="color:var(--ok)">✓ Wiped from device.</span>';
  else document.getElementById('apply-msg').innerHTML='<span style="color:var(--crit)">✗ '+(r?esc(r.error||r.detail):'failed')+'</span>';
  loadServers(); loadLogs();
}
async function loadLogs(){
  const r=await fetch('wireguard.php?api=logs&server='+SEL).then(r=>r.json()).catch(()=>null);
  document.getElementById('logs-body').innerHTML = (r&&r.logs&&r.logs.length)? r.logs.map(l=>`<tr>
    <td class="muted">${esc(l.created_at)}</td><td>${esc(l.action)}</td><td>${esc(l.target_type)}</td>
    <td>${l.ok==1?'<span style="color:var(--ok)">✓</span>':'<span style="color:var(--crit)">✗</span>'}</td>
    <td class="mono" style="font-size:10px;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(l.detail)}">${esc((l.detail||'').slice(0,120))}</td></tr>`).join('')
    : '<tr><td colspan="5" class="muted">No apply history.</td></tr>';
}
// ── Adopt existing WireGuard from a monitored device ──
function openScan(){ document.getElementById('sc-node').value=''; document.getElementById('sc-result').innerHTML='<span class="muted">Pick a device and Scan — NEURU will SSH in and read its WireGuard config.</span>'; document.getElementById('scanbg').style.display='flex'; }
async function runScan(){
  const node=document.getElementById('sc-node').value; if(!node){ alert('Pick a device'); return; }
  const box=document.getElementById('sc-result'); box.innerHTML='<span class="muted"><i class="fas fa-spinner fa-spin"></i> Scanning over SSH…</span>';
  const r=await fetch('wireguard.php?api=discover&node='+node).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ box.innerHTML='<span style="color:var(--crit)">✗ '+(r?esc(r.error):'scan failed')+'</span>'; return; }
  if(!r.interfaces.length){ box.innerHTML='<div class="muted">No WireGuard interfaces found on <b>'+esc(r.node.name)+'</b>. Use “Create new (greenfield)” to build one.</div>'; return; }
  box.innerHTML='<div class="muted" style="margin-bottom:8px;">Found '+r.interfaces.length+' interface(s) on <b>'+esc(r.node.name)+'</b> ('+esc(r.target_type)+'). Adopt one to manage its peers:</div>'+
    r.interfaces.map((i,idx)=>`<div class="glass" style="padding:12px;margin-bottom:10px;">
      <div style="font-weight:700;">${esc(i.name)} <span class="tt">:${i.listen_port}</span> <span class="muted">${i.peers.length} peer(s)</span></div>
      <div class="mono muted" style="font-size:10px;margin:3px 0 8px;word-break:break-all;">pub ${esc((i.public_key||'').slice(0,32))}…${i.address?' · addr '+esc(i.address):''}</div>
      <div class="row">
        <div><label style="font-size:10px;color:#8a909a;">Public endpoint (peers dial)</label><input id="ad-ep-${idx}" value="${esc(r.node.ip)}"></div>
        <div><label style="font-size:10px;color:#8a909a;">VPN subnet (IPAM, for auto peer IPs)</label><select id="ad-sub-${idx}">${subnetOpts()}</select></div>
      </div>
      <label style="display:flex;gap:8px;align-items:center;margin-top:8px;font-size:12px;"><input type="checkbox" id="ad-imp-${idx}" style="width:auto;" ${i.peers.length?'checked':''}> Import its ${i.peers.length} existing peer(s) for visibility (read-only)</label>
      <div style="margin-top:8px;"><button class="btn" onclick='adoptIface(${node},${JSON.stringify(i.name)},${idx},${JSON.stringify(i.address||"")})'><i class="fas fa-circle-down"></i> Adopt this interface</button></div>
    </div>`).join('');
}
async function adoptIface(node,ifn,idx,addr){
  const b=new URLSearchParams({action:'adopt',node_id:node,iface_name:ifn,endpoint_host:gv('ad-ep-'+idx),vpn_subnet_id:gv('ad-sub-'+idx),address_cidr:addr});
  if(document.getElementById('ad-imp-'+idx).checked) b.set('import_peers','1');
  const r=await post(b);
  if(r&&r.ok){ closeM('scanbg'); SEL=r.id; loadServers(); alert('Adopted '+ifn+(r.imported?' · imported '+r.imported+' peer(s)':'')+'.\nNow open the Peers tab to add new peers.'); }
  else alert(r?r.error:'adopt failed');
}
loadServers();
</script>
</body></html>
