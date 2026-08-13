<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Licensing (Site Configuration). Where an admin points this install at
// the NEURU License Portal, activates a license key, sees the live entitlement
// state (tier / nodes / grace / fingerprint), revalidates, deactivates, and
// toggles enforcement. Client engine: nm_license.php (verifies Ed25519 tokens with
// the embedded public key; the private key never touches this install). Admin-only.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_license.php');
require_once('nm_audit.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'license')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=license'); exit;
}
$isAdmin = (($_SESSION['role'] ?? '') === 'admin');
nm_lic_ensure($conn);

if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $needAdmin = function() use ($isAdmin){ if(!$isAdmin){ echo json_encode(['ok'=>false,'error'=>'admin only']); exit; } };
    try {
        if ($api === 'status') {
            $st = nm_lic_state($conn); $row = nm_lic_row($conn);
            echo json_encode(['ok'=>true,
                'state'=>$st,
                'fingerprint'=>nm_lic_fingerprint(),
                'api_url'=>nm_lic_api_base($conn),
                'enforced'=>nm_lic_enforced($conn),
                'active_tier'=>nm_lic_active_tier($conn),
                'node_count'=>nm_lic_node_count($conn),
                'row'=>$row ? ['status'=>$row['status'],'tier'=>$row['tier'],'max_nodes'=>$row['max_nodes'],
                    'grace_until'=>$row['grace_until'],'last_check'=>$row['last_check'],'last_error'=>$row['last_error'],
                    'offline'=>(int)$row['offline'],'license_key'=>$row['license_key']] : null,
                'app_version'=>nm_lic_app_version($conn),
            ]); exit;
        }
        if ($api === 'save') { $needAdmin();
            // The portal API URL is product-controlled (shipped with the build, updated via
            // updates) — the field is read-only, so we intentionally IGNORE any posted api_url.
            nm_lic_set_setting($conn, 'license_enforce', !empty($body['enforce']) ? '1' : '0');
            nm_audit($conn,'license.settings',['details'=>['enforce'=>!empty($body['enforce'])?1:0]]);
            echo json_encode(['ok'=>true]); exit;
        }
        if ($api === 'activate') { $needAdmin();
            $key = strtoupper(trim((string)($body['license_key'] ?? '')));
            if ($key === '') { echo json_encode(['ok'=>false,'error'=>'Enter a license key']); exit; }
            $r = nm_lic_activate($conn, $key);
            nm_audit($conn,'license.activate',['details'=>['ok'=>!empty($r['ok'])]]);
            echo json_encode($r); exit;
        }
        if ($api === 'validate') { $needAdmin(); echo json_encode(nm_lic_validate($conn)); exit; }
        if ($api === 'deactivate') { $needAdmin(); $r=nm_lic_deactivate($conn); nm_audit($conn,'license.deactivate',[]); echo json_encode($r); exit; }
        if ($api === 'billing') { echo json_encode(nm_lic_billing($conn)); exit; }   // customer transparency: plan · next payment · AI credits
        echo json_encode(['ok'=>false,'error'=>'unknown api']);
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn,'view_page','license.php');
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
html{background:#05080f} body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:transparent!important;color:#d4dce8}
<?= nm_chrome_css() ?>
.lic{max-width:960px;margin:0 auto;padding:20px 22px 60px}
.glass{background:rgba(12,16,26,.62);backdrop-filter:blur(13px);border:1px solid rgba(255,255,255,.12);border-radius:14px}
.bar{display:flex;align-items:center;gap:12px;padding:14px 18px;margin-bottom:16px}
.title{font-size:19px;font-weight:800;display:flex;align-items:center;gap:11px}.title i{color:#36e3d0}
.card{padding:20px 22px;margin-bottom:16px}
.hero-st{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.badge{font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:1px;padding:7px 16px;border-radius:24px;display:inline-flex;align-items:center;gap:8px}
.badge.enterprise{background:linear-gradient(135deg,rgba(54,227,208,.2),rgba(77,163,255,.2));border:1px solid rgba(54,227,208,.5);color:#8ff0e4}
.badge.pro{background:rgba(77,163,255,.16);border:1px solid rgba(77,163,255,.5);color:#bcd8ff}
.badge.free,.badge.perpetual{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.2);color:#cdd6e2}
.badge.unlicensed{background:rgba(240,169,44,.14);border:1px solid rgba(240,169,44,.45);color:#ffd98a}
.dot{width:11px;height:11px;border-radius:50%;box-shadow:0 0 9px currentColor;display:inline-block}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-top:18px}
.kv{background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.08);border-radius:11px;padding:12px 14px}
.kv .l{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:#7f93af}.kv .v{font-size:16px;font-weight:700;color:#e6edf7;margin-top:3px;word-break:break-word}
label{display:block;font-size:10.5px;text-transform:uppercase;letter-spacing:.4px;color:#8b95a7;margin:14px 0 6px}
.inp{width:100%;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.12);color:#e6edf7;border-radius:9px;padding:11px 13px;font-size:14px;font-family:inherit}
.mono{font-family:Consolas,monospace}
.btn{display:inline-flex;align-items:center;gap:8px;background:rgba(77,163,255,.14);border:1px solid rgba(77,163,255,.4);color:#cfe4ff;border-radius:9px;padding:10px 16px;font-size:13px;cursor:pointer;font-weight:600}
.btn:hover{border-color:#4da3ff;color:#fff}.btn.g{background:linear-gradient(135deg,#36e3d0,#4da3ff);border:none;color:#04121a;font-weight:700}.btn.danger{border-color:rgba(255,90,90,.45);color:#ff9b91}.btn:disabled{opacity:.5;cursor:not-allowed}
.muted{color:#8a97ab;font-size:13px}.hint{font-size:12px;color:#7f93af;margin-top:6px}
.switch{display:inline-flex;align-items:center;gap:10px;cursor:pointer;font-size:14px}
.switch input{width:42px;height:22px;appearance:none;background:rgba(255,255,255,.14);border-radius:20px;position:relative;cursor:pointer;transition:.2s}
.switch input:checked{background:#36e3d0}.switch input::after{content:'';position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:#fff;transition:.2s}.switch input:checked::after{left:22px}
.msg{font-size:13px;margin-top:10px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.note{background:rgba(77,163,255,.06);border:1px solid rgba(77,163,255,.22);border-radius:11px;padding:12px 14px;font-size:12.5px;color:#a8c4e8;margin-top:14px}
</style>
<div class="lic">
  <div class="bar glass">
    <div class="title"><i class="fa-solid fa-certificate"></i> Licensing</div>
    <span class="muted" id="appv"></span>
    <span style="flex:1"></span>
    <button class="btn" onclick="load()"><i class="fa-solid fa-rotate"></i> Refresh</button>
  </div>

  <!-- FREE LICENSE CTA -->
  <div class="glass card" style="border:1px solid rgba(54,227,208,.35);background:rgba(54,227,208,.06)">
    <b style="font-size:15px"><i class="fa-solid fa-unlock-keyhole" style="color:#36e3d0"></i> NEURU is free &amp; open source</b>
    <div class="hint" style="margin-top:6px">Your license is <b>free, unlimited and never expires</b> (10 activations, any OS). Don't have one yet? Create a free account at <a href="https://neurunetpr.com" target="_blank" rel="noopener" style="color:#8bf3ff">neurunetpr.com</a> — <b>register</b>, then copy your key from <b>Licensing</b> in your portal account and paste it below. We only ever charge for optional AI usage. Source: <a href="https://github.com/hmiranda14/neuru" target="_blank" rel="noopener" style="color:#8bf3ff"><i class="fa-brands fa-github"></i> github.com/hmiranda14/neuru</a>.</div>
  </div>

  <!-- STATUS -->
  <div class="glass card">
    <div class="hero-st">
      <span class="badge unlicensed" id="tierBadge"><span class="dot"></span> <span id="tierTxt">…</span></span>
      <div>
        <div style="font-weight:700;font-size:15px" id="stTxt">Loading…</div>
        <div class="muted" id="stSub"></div>
      </div>
    </div>
    <div class="grid2" id="kvs"></div>
  </div>

  <!-- BILLING & BALANCE (100% transparency — visible to every user) -->
  <div class="glass card" id="billCard">
    <b style="font-size:15px"><i class="fa-solid fa-wallet" style="color:#36e3d0"></i> Billing &amp; Balance</b>
    <div class="hint" id="billHint">Loading your plan, next payment, and AI credits…</div>
    <div id="billKvs" style="margin-top:12px;display:grid;grid-template-columns:1fr 1fr;gap:10px 22px"></div>
    <div id="billLedger" style="margin-top:14px"></div>
  </div>

  <?php if ($isAdmin): ?>
  <!-- ACTIVATE -->
  <div class="glass card">
    <b style="font-size:15px"><i class="fa-solid fa-key" style="color:#36e3d0"></i> Activate a license</b>
    <div class="hint">Paste the license key from your NEURU portal account. This install binds to this machine's fingerprint and receives a signed token.</div>
    <label>License key</label>
    <div class="row"><input class="inp mono" id="key" placeholder="NEURU-XXXX-XXXX-XXXX-XXXX" style="max-width:340px;text-transform:uppercase">
      <button class="btn g" onclick="activate()"><i class="fa-solid fa-bolt"></i> Activate</button></div>
    <div class="msg" id="actMsg"></div>
    <div class="row" style="margin-top:16px">
      <button class="btn" onclick="validate()"><i class="fa-solid fa-arrows-rotate"></i> Revalidate now</button>
      <button class="btn danger" onclick="deactivate()"><i class="fa-solid fa-link-slash"></i> Deactivate this machine</button>
    </div>
  </div>

  <!-- SETTINGS -->
  <div class="glass card">
    <b style="font-size:15px"><i class="fa-solid fa-sliders" style="color:#4da3ff"></i> Portal &amp; enforcement</b>
    <label>License portal API URL <span style="color:#5b6b7a;font-weight:400">· managed by updates</span></label>
    <input class="inp mono" id="apiUrl" readonly disabled title="This is set by the product and updated through releases — it can't be changed here." style="opacity:.55;cursor:not-allowed;background:rgba(255,255,255,.03)">
    <div class="hint"><i class="fa-solid fa-lock" style="opacity:.6"></i> Product-controlled: the portal endpoint ships with NEURU and is updated through releases, not edited here. Activation &amp; heartbeats POST to <code>&lt;url&gt;/v1/…</code>.</div>
    <label>Enforcement</label>
    <label class="switch"><input type="checkbox" id="enforce"> <span>Enforce license tier (gate paid features)</span></label>
    <div class="hint">Default OFF — NEURU runs fully (nothing gated). When ON, pages that carry a feature-gate check the verified token's tier. Your install stays whatever your token grants.</div>
    <div class="row" style="margin-top:16px"><button class="btn g" onclick="save()"><i class="fa-solid fa-floppy-disk"></i> Save</button><span class="msg" id="setMsg"></span></div>
    <div class="note" id="ownerNote" style="display:none"><i class="fa-solid fa-crown" style="color:#f0c04a"></i> This install holds a <b>perpetual/offline</b> token — leave it as-is. Re-activating would replace it with a shorter online token.</div>
  </div>
  <?php else: ?>
  <div class="glass card muted">Licensing settings are admin-only. You can view the status above.</div>
  <?php endif; ?>
</div>
<script>
const IS_ADMIN=<?= $isAdmin?'true':'false' ?>;
const E=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function tierColor(t){return t==='enterprise'?'#36e3d0':t==='pro'?'#4da3ff':t==='unlicensed'?'#f0a92c':'#9fb2c8';}
// Timestamps are stored UTC (canonical). Render them in the admin's configured display timezone
// (window.nmLocal / NM_TZ from nm_tz_js). Only convert values that CARRY A TIME — a bare date
// (license expiry, next-payment date) must NOT be shifted a day by a tz offset, so it stays as-is.
function fmtDate(d){
  if(!d) return '—';
  var s = String(d);
  if(window.nmLocal && /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s)) return window.nmLocal(s);
  return s.replace('T',' ').slice(0,16);
}
async function load(){
  const r=await fetch('license.php?api=status&_='+Date.now()).then(x=>x.json()).catch(()=>null);
  if(!r||!r.ok)return;
  document.getElementById('appv').textContent='v'+r.app_version;
  const st=r.state, row=r.row||{};
  const tier=st.tier||'unlicensed';
  const b=document.getElementById('tierBadge'); b.className='badge '+tier; b.querySelector('.dot').style.color=tierColor(tier);
  document.getElementById('tierTxt').textContent=tier.toUpperCase();
  const valid=st.valid, forever=(row.grace_until && new Date(row.grace_until).getFullYear()>=2090);
  const isFree=(tier==='free');
  document.getElementById('stTxt').textContent = valid
    ? (forever?'Licensed · perpetual / offline':(isFree?'Licensed · Free (never expires)':'Licensed · '+(st.status||'active')))
    : (r.enforced?'Not licensed — running as free (enforcement ON)':'Unlicensed (enforcement off — full product)');
  document.getElementById('stSub').textContent = valid && isFree
    ? 'Free license never expires — it just heartbeats with the portal automatically'
    : (r.enforced ? 'Enforcement is ON' : 'Enforcement is OFF — nothing is gated');
  const nodeLimitVal = st.max_nodes==null ? (valid?'Unlimited':'—')
    : (st.max_nodes + (r.enforced ? '' : ' (not enforced)'));
  document.getElementById('kvs').innerHTML=[
    ['Effective tier', (r.active_tier||'—').toUpperCase()],
    ['Node limit', nodeLimitVal],
    ['Nodes in use', (r.node_count==null?'—':r.node_count)],
    ['Status', row.status||st.status||'—'],
    ['Valid token', valid?'Yes':'No'],
    ['Expires', forever?'Never (perpetual)':(isFree&&valid?'Never · auto-revalidates':fmtDate(row.grace_until))],
    ['Last heartbeat', fmtDate(row.last_check)],
    ['License key', row.license_key?E(row.license_key.slice(0,10)+'…'):'—'],
    ['Machine fingerprint', '<span class="mono" style="font-size:12px">'+E((r.fingerprint||'').slice(0,20))+'…</span>'],
  ].map(k=>'<div class="kv"><div class="l">'+k[0]+'</div><div class="v">'+k[1]+'</div></div>').join('');
  if(row.last_error){ document.getElementById('stSub').innerHTML+=' · <span style="color:#ffb0b0">'+E(row.last_error)+'</span>'; }
  if(IS_ADMIN){
    document.getElementById('apiUrl').value=r.api_url||'';
    document.getElementById('enforce').checked=!!r.enforced;
    document.getElementById('ownerNote').style.display=forever?'block':'none';
  }
  loadBilling();
}
function _money(c){ return '$'+(Math.max(0,(c|0))/100).toFixed(2); }
async function loadBilling(){
  const hint=document.getElementById('billHint'), kvs=document.getElementById('billKvs'), led=document.getElementById('billLedger');
  const r=await fetch('license.php?api=billing&_='+Date.now()).then(x=>x.json()).catch(()=>null);
  if(!r||!r.ok){ hint.textContent=(r&&r.error)?r.error:'Billing is unavailable right now.'; kvs.innerHTML=''; led.innerHTML=''; return; }
  const plan=r.plan||{}, sub=r.subscription, ai=r.ai||{};
  hint.innerHTML = r.stripe_configured
    ? 'Your live plan, next payment, and AI credit balance.'
    : '<i class="fa-solid fa-circle-info" style="opacity:.7"></i> Online payments aren\'t set up yet — the balances below are shown for full transparency.';
  const kv=[];
  kv.push(['Plan', E(plan.name||'—')+(plan.billing_type?' · '+E(plan.billing_type):'')]);
  if(sub){
    kv.push(['Subscription', E(String(sub.status||'—').toUpperCase())+(sub.cancel_at_period_end?' · cancels at period end':'')]);
    kv.push(['Monthly balance', _money(sub.monthly_cents)+' <span class="l" style="font-size:11px">/ mo</span>']);
    kv.push(['Next payment', sub.next_payment?fmtDate(sub.next_payment):'—']);
  } else {
    kv.push(['Subscription', 'None — Free plan']);
    kv.push(['Monthly balance', '$0.00 · Free never bills']);
  }
  kv.push(['<span style="color:#36e3d0">AI credits remaining</span>', '<b style="color:#36e3d0;font-size:16px">'+_money(ai.credit_cents)+'</b>']);
  kvs.innerHTML = kv.map(k=>'<div class="kv"><div class="l">'+k[0]+'</div><div class="v">'+k[1]+'</div></div>').join('');
  const rec=r.recent||[];
  led.innerHTML = rec.length ? ('<div class="l" style="margin-bottom:6px">Recent AI activity</div>'+
    '<table style="width:100%;border-collapse:collapse;font-size:12px">'+rec.map(x=>{
      const amt=(x.amount_cents|0), pos=amt>=0, col=pos?'#8ff0b6':'#ffb0b0';
      return '<tr><td style="padding:3px 6px;color:#8a97ab;white-space:nowrap">'+fmtDate(x.created_at)+'</td>'+
        '<td style="padding:3px 6px">'+E(x.note||x.type||'')+'</td>'+
        '<td style="padding:3px 6px;text-align:right;color:'+col+'">'+(pos?'+':'−')+_money(Math.abs(amt))+'</td>'+
        '<td style="padding:3px 6px;text-align:right;color:#8a97ab">'+_money(x.balance_after_cents)+'</td></tr>';
    }).join('')+'</table>') : '';
}
async function save(){
  const r=await fetch('license.php?api=save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({api_url:document.getElementById('apiUrl').value,enforce:document.getElementById('enforce').checked})}).then(x=>x.json());
  const m=document.getElementById('setMsg'); m.textContent=r.ok?'✓ Saved':(r.error||'failed'); m.style.color=r.ok?'#8ff0b6':'#ffb0b0'; if(r.ok)load();
}
async function activate(){
  const m=document.getElementById('actMsg'); m.textContent='Activating…'; m.style.color='#9fb2c8';
  const r=await fetch('license.php?api=activate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({license_key:document.getElementById('key').value})}).then(x=>x.json());
  m.innerHTML=r.ok?'<span style="color:#8ff0b6">✓ Activated — '+E(r.state?.tier||'')+'</span>':'<span style="color:#ffb0b0">✗ '+E(r.error||'failed')+'</span>'; if(r.ok){document.getElementById('key').value='';load();}
}
async function validate(){
  const r=await fetch('license.php?api=validate',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(x=>x.json());
  const m=document.getElementById('actMsg'); m.innerHTML=r.ok?('<span style="color:#8ff0b6">✓ Revalidated'+(r.warning?' — '+E(r.warning):'')+'</span>'):'<span style="color:#ffb0b0">✗ '+E(r.error||'failed')+'</span>'; load();
}
async function deactivate(){
  if(!confirm('Deactivate this machine? It frees the activation slot and clears the local token. If this install holds a perpetual/offline license you would lose it.'))return;
  const r=await fetch('license.php?api=deactivate',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(x=>x.json());
  document.getElementById('actMsg').innerHTML=r.ok?'<span style="color:#ffd98a">Deactivated.</span>':'<span style="color:#ffb0b0">'+E(r.error||'failed')+'</span>'; load();
}
load();
</script>
