<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Widget Marketplace. Browse every available widget: official NEURU
// widgets (curated, author "NEURU", non-deletable) and Community widgets (created
// by users). See each one's full code to learn from, preview it live, install it
// to your Command Center, or — for your OWN community widgets — delete it.
// RBAC: 'command'. Shares nm_widgetkit.js (render/install/remove) + command.php API.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_widgets.php';
require_once __DIR__ . '/nm_chrome.php';
include __DIR__ . '/check.php';
if (!checkAccess($conn, 'command')) { header('Location: /denied_access.php?page=command'); exit; }
require_once __DIR__ . '/logger.php';
log_user_action($conn, 'view_page', 'widget_market.php');
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];
nm_widgets_ensure($conn);
include __DIR__ . '/header.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Widget Marketplace | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/nm_widgetkit.js"></script>
<style>
<?= nm_chrome_css() ?>
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; overflow-x:hidden; }
a{ color:#4da3ff; }
.mk{ max-width:1280px; margin:0 auto; padding:18px 22px 70px; }
.mk-head{ display:flex; align-items:center; gap:12px; margin-bottom:4px; }
.mk-head h1{ font-size:23px; font-weight:800; margin:0; } .mk-head i{ color:#4da3ff; }
.mk-sub{ color:#9aa3ad; font-size:13px; margin:0 0 18px; }
.mk-bar{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:20px; }
.mk-search{ background:#1b2129; color:#e6e9ee; border:1px solid rgba(255,255,255,.14); border-radius:9px; padding:9px 13px; font-size:13px; min-width:240px; }
.chip{ cursor:pointer; font-size:12px; font-weight:600; color:#9aa3ad; background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.12); border-radius:20px; padding:6px 13px; }
.chip.on{ background:rgba(77,163,255,.18); border-color:#4da3ff; color:#fff; }
.sec-h{ display:flex; align-items:center; gap:10px; font-size:14px; font-weight:800; margin:22px 0 12px; }
.sec-h .tag{ font-size:10px; padding:2px 9px; border-radius:10px; text-transform:uppercase; letter-spacing:1px; }
.tag-neuru{ background:rgba(77,163,255,.18); color:#7dd3fc; } .tag-comm{ background:rgba(46,204,113,.16); color:#7fe0a3; }
.sec-h .cnt{ color:#6b7280; font-weight:600; font-size:12px; }
.grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(310px,1fr)); gap:16px; }
.wcard{ background:rgba(255,255,255,.045); border:1px solid rgba(255,255,255,.12); border-radius:14px; padding:15px 16px; display:flex; flex-direction:column; }
.wcard .top{ display:flex; align-items:center; gap:11px; }
.wcard .ic{ width:40px; height:40px; flex:0 0 auto; border-radius:11px; background:rgba(77,163,255,.12); display:flex; align-items:center; justify-content:center; font-size:18px; color:#4da3ff; }
.wcard .nm{ font-weight:700; font-size:14.5px; }
.wcard .by{ font-size:10.5px; color:#8a929c; } .wcard .by b{ color:#bcd; }
.author{ font-size:9.5px; padding:1px 7px; border-radius:9px; text-transform:uppercase; letter-spacing:.5px; }
.author.neuru{ background:rgba(77,163,255,.16); color:#9cc7f5; } .author.comm{ background:rgba(46,204,113,.14); color:#86e0aa; }
.cat{ font-size:10px; color:#7c828c; margin-left:auto; align-self:flex-start; border:1px solid rgba(255,255,255,.1); border-radius:8px; padding:1px 7px; }
.desc{ color:#aab2bc; font-size:12.5px; line-height:1.55; margin:10px 0 12px; flex:1; }
.acts{ display:flex; gap:7px; flex-wrap:wrap; }
.b{ display:inline-flex; align-items:center; gap:6px; cursor:pointer; font-size:11.5px; font-weight:600; color:#cfd6df; background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.13); border-radius:8px; padding:6px 11px; }
.b:hover{ border-color:#4da3ff; color:#fff; } .b.ok{ color:#7fe0a3; border-color:rgba(46,204,113,.4); } .b.ok:hover{ background:rgba(46,204,113,.16); }
.b.del:hover{ border-color:#e74c3c; color:#f0a59d; }
.codebox,.prevbox{ display:none; margin-top:11px; }
.codebox pre{ background:#0a0e15; border:1px solid rgba(255,255,255,.12); border-radius:9px; padding:11px 12px; overflow:auto; max-height:240px; font-size:11px; line-height:1.5; color:#cfe4ff; margin:0; }
.codebar{ display:flex; justify-content:flex-end; margin-bottom:5px; }
.prevbox{ background:rgba(8,12,19,.7); border:1px solid rgba(255,255,255,.13); border-radius:10px; padding:8px 10px; max-height:240px; overflow:auto; }
.empty{ color:#5b6470; font-size:12.5px; text-align:center; padding:20px 0; }
</style>
</head>
<body>
<div class="mk">
  <div class="mk-head"><i class="fa-solid fa-store"></i><h1>Widget Marketplace</h1></div>
  <p class="mk-sub">Browse, preview and install widgets — or read their code to learn how to build your own.
     <a href="widgets.php">Open Widget Studio</a> · <a href="widget_sdk.php">SDK guide</a></p>
  <div class="mk-bar">
    <input class="mk-search" id="mk-q" placeholder="Search widgets…" oninput="setQ(this.value)">
    <div id="mk-cats" style="display:flex;gap:8px;flex-wrap:wrap;"></div>
  </div>
  <div id="mk-body"><div class="empty">Loading marketplace…</div></div>
</div>

<script>
const CSRF=<?= json_encode($CSRF) ?>;
let DATA={official:[],community:[]}, FILTER={q:'',cat:''};
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function clean(m){ const o={}; for(const k in m){ if(k[0]!=='_') o[k]=m[k]; } return o; }
function toast(msg){ let t=document.getElementById('mk-toast'); if(!t){ t=document.createElement('div'); t.id='mk-toast';
  t.style.cssText='position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#11151d;border:1px solid rgba(255,255,255,.14);border-left:4px solid #4da3ff;border-radius:10px;padding:11px 18px;font-size:13px;z-index:3000;color:#fff;'; document.body.appendChild(t); }
  t.textContent=msg; t.style.opacity='1'; clearTimeout(t._h); t._h=setTimeout(()=>t.style.opacity='0',2200); }
function copyText(str,btn){ const ok=()=>{ const o=btn.innerHTML; btn.innerHTML='<i class="fa-solid fa-check"></i> Copied'; setTimeout(()=>btn.innerHTML=o,1400); };
  if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(str).then(ok).catch(()=>fb()); } else fb();
  function fb(){ const ta=document.createElement('textarea'); ta.value=str; ta.style.position='fixed'; ta.style.top='-9999px'; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy');ok();}catch(e){} document.body.removeChild(ta); } }

function setQ(v){ FILTER.q=v.trim().toLowerCase(); render(); }
function setCat(c){ FILTER.cat=(FILTER.cat===c?'':c); render(); }
function allCats(){ const s=new Set(); [...DATA.official,...DATA.community].forEach(m=>{ if(m.category)s.add(m.category); }); return [...s].sort(); }
function matches(m){ const q=FILTER.q; const hay=((m.name||'')+' '+(m.description||'')+' '+(m.id||'')+' '+(m._author||'')+' '+(m.category||'')).toLowerCase();
  return (!q||hay.includes(q)) && (!FILTER.cat||m.category===FILTER.cat); }

const REG=[]; // flat registry of rendered cards → manifest, for button handlers
function cardHTML(m,i){ const isN=m._source==='neuru';
  return `<div class="wcard" data-i="${i}">
    <div class="top"><div class="ic"><i class="fa-solid ${esc(m.icon||'fa-puzzle-piece')}"></i></div>
      <div style="min-width:0;"><div class="nm">${esc(m.name||m.id)}</div>
        <div class="by">by <span class="author ${isN?'neuru':'comm'}">${isN?'NEURU':esc(m._author||'community')}</span></div></div>
      <span class="cat">${esc(m.category||'')}</span></div>
    <div class="desc">${esc(m.description||'No description.')}</div>
    <div class="acts">
      <span class="b ok" data-act="install"><i class="fa-solid fa-download"></i> Install</span>
      <span class="b" data-act="preview"><i class="fa-solid fa-eye"></i> Preview</span>
      <span class="b" data-act="code"><i class="fa-solid fa-code"></i> Code</span>
      ${m._mine?`<span class="b del" data-act="del"><i class="fa-solid fa-trash"></i> Delete</span>`:''}
    </div>
    <div class="prevbox"></div>
    <div class="codebox"><div class="codebar"><span class="b" data-act="copy"><i class="fa-solid fa-copy"></i> Copy</span></div>
      <pre><code>${esc(JSON.stringify(clean(m),null,2))}</code></pre></div>
  </div>`;
}
function render(){
  document.getElementById('mk-cats').innerHTML = allCats().map(c=>`<span class="chip ${FILTER.cat===c?'on':''}" data-cat="${esc(c)}">${esc(c)}</span>`).join('');
  document.querySelectorAll('#mk-cats .chip').forEach(ch=>ch.onclick=()=>setCat(ch.dataset.cat));
  REG.length=0;
  const off=DATA.official.filter(matches), com=DATA.community.filter(matches);
  const sec=(title,tag,tagcls,arr)=>{ if(!arr.length) return '';
    return `<div class="sec-h"><span class="tag ${tagcls}">${tag}</span> ${title} <span class="cnt">${arr.length}</span></div>
      <div class="grid">${arr.map(m=>{ REG.push(m); return cardHTML(m,REG.length-1); }).join('')}</div>`; };
  const html = sec('NEURU Widgets','official','tag-neuru',off) + sec('Community Widgets','community','tag-comm',com);
  document.getElementById('mk-body').innerHTML = html || '<div class="empty">No widgets match your search.</div>';
  document.querySelectorAll('.wcard').forEach(card=>{ const m=REG[+card.dataset.i];
    card.querySelectorAll('[data-act]').forEach(b=>b.onclick=()=>action(b.dataset.act,m,card,b)); });
}
async function action(act,m,card,btn){
  if(act==='install'){ const r=await NMWidgetKit.apiInstall(clean(m),'user','command.php',CSRF);
    toast((r&&r.ok)?'Installed — it’s on your Command Center':((r&&r.errors)?r.errors[0]:'Install failed')); return; }
  if(act==='copy'){ copyText(JSON.stringify(clean(m),null,2), btn); return; }
  if(act==='code'){ const box=card.querySelector('.codebox'); box.style.display=box.style.display==='block'?'none':'block'; return; }
  if(act==='preview'){ const box=card.querySelector('.prevbox');
    if(box.style.display==='block'){ box.style.display='none'; if(box._t)clearInterval(box._t); return; }
    box.style.display='block'; NMWidgetKit.mountDeclarative(clean(m), box, 'command.php'); return; }
  if(act==='del'){ if(!confirm('Delete your widget “'+(m.name||m.id)+'”? This cannot be undone.')) return;
    const r=await NMWidgetKit.apiRemove(m.id,'command.php',CSRF); toast((r&&r.ok)?'Deleted':'Could not delete'); loadMarket(); return; }
}
async function loadMarket(){ let r; try{ r=await fetch('command.php?api=marketplace').then(x=>x.json()); }catch(e){ r=null; }
  if(!r||!r.ok){ document.getElementById('mk-body').innerHTML='<div class="empty">Could not load the marketplace.</div>'; return; }
  DATA={official:r.official||[],community:r.community||[]}; render(); }
loadMarket();
</script>
</body></html>
