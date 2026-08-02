<?php
// NetMon — NetOps Copilot slide-out chat widget. Included globally by header.php
// (only when the user has 'copilot' access). Self-contained: scoped #nmcp-* IDs,
// fixed positioning, own style+script. Talks to nm_copilot.php (server-side proxy).
?>
<button id="nmcp-fab" title="Ask the NetOps Copilot" onclick="nmcpToggle()">
    <i class="fa-solid fa-wand-magic-sparkles"></i>
</button>

<div id="nmcp-panel" aria-hidden="true">
    <div id="nmcp-head">
        <div class="nmcp-title"><i class="fa-solid fa-wand-magic-sparkles"></i> NetOps Copilot
            <span id="nmcp-status"></span></div>
        <div>
            <button class="nmcp-ic" title="Clear conversation" onclick="nmcpClear()"><i class="fa-solid fa-broom"></i></button>
            <button class="nmcp-ic" title="Close" onclick="nmcpToggle()"><i class="fa-solid fa-xmark"></i></button>
        </div>
    </div>
    <div id="nmcp-msgs"></div>
    <div id="nmcp-suggest">
        <button onclick="nmcpAsk(this.textContent)">How do I add a node?</button>
        <button onclick="nmcpAsk(this.textContent)">Where do I tune false down alarms?</button>
        <button onclick="nmcpAsk(this.textContent)">How do I create a widget?</button>
        <button onclick="nmcpAsk(this.textContent)">Who's using bandwidth right now?</button>
        <button onclick="nmcpAsk(this.textContent)">Summarize current incidents</button>
    </div>
    <div id="nmcp-input">
        <textarea id="nmcp-q" rows="1" placeholder="Ask about the network or how to use NEURU…"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();nmcpSend();}"></textarea>
        <button id="nmcp-send" onclick="nmcpSend()"><i class="fa-solid fa-paper-plane"></i></button>
    </div>
</div>

<style>
#nmcp-fab{ position:fixed; right:22px; bottom:22px; width:54px; height:54px; border-radius:50%;
    background:linear-gradient(135deg,#9b59b6,#4da3ff); color:#fff; border:none; cursor:pointer;
    font-size:20px; box-shadow:0 6px 22px rgba(155,89,182,.5); z-index:3000; transition:transform .15s; }
#nmcp-fab:hover{ transform:scale(1.08); }
#nmcp-panel{ position:fixed; right:-440px; bottom:0; top:0; width:420px; max-width:92vw; z-index:3001;
    background:rgba(12,15,22,.97); backdrop-filter:blur(18px); border-left:1px solid rgba(255,255,255,.12);
    box-shadow:-10px 0 40px rgba(0,0,0,.5); display:flex; flex-direction:column; transition:right .28s ease; }
#nmcp-panel.open{ right:0; }
#nmcp-head{ display:flex; align-items:center; justify-content:space-between; padding:14px 16px;
    border-bottom:1px solid rgba(255,255,255,.1); background:rgba(155,89,182,.08); }
.nmcp-title{ font:600 14px 'Segoe UI',sans-serif; color:#fff; display:flex; align-items:center; gap:8px; }
.nmcp-title i{ color:#c08fd6; }
#nmcp-status{ font-size:10px; font-weight:400; padding:2px 7px; border-radius:10px; }
.nmcp-ic{ background:none; border:none; color:#888; cursor:pointer; font-size:15px; padding:4px 7px; }
.nmcp-ic:hover{ color:#fff; }
#nmcp-msgs{ flex:1; overflow-y:auto; padding:16px; display:flex; flex-direction:column; gap:12px; }
.nmcp-msg{ max-width:88%; padding:10px 13px; border-radius:12px; font:13px/1.55 'Segoe UI',sans-serif; white-space:pre-wrap; word-break:break-word; }
.nmcp-user{ align-self:flex-end; background:rgba(77,163,255,.18); border:1px solid rgba(77,163,255,.35); color:#dbeeff; }
.nmcp-ai{ align-self:flex-start; background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.1); color:#e3e6ea; }
.nmcp-ai b{ color:#fff; } .nmcp-ai code{ background:rgba(0,0,0,.4); padding:1px 5px; border-radius:4px; font-size:12px; color:#7fd1ff; }
.nmcp-ev{ margin-top:9px; border-top:1px dashed rgba(255,255,255,.12); padding-top:8px; font-size:11.5px; }
.nmcp-ev .h{ color:#888; text-transform:uppercase; letter-spacing:1px; font-size:9px; margin-bottom:4px; }
.nmcp-ev div{ color:#9aa; padding:2px 0; }
.nmcp-diag{ margin-top:9px; background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.1); border-radius:8px; padding:9px; font-family:Consolas,monospace; font-size:11px; color:#8fb; overflow-x:auto; }
.nmcp-think{ align-self:flex-start; color:#888; font-size:12px; display:flex; gap:8px; align-items:center; }
.nmcp-empty{ color:#667; text-align:center; padding:30px 16px; font-size:13px; }
.nmcp-empty i{ font-size:30px; color:#9b59b6; display:block; margin-bottom:10px; }
#nmcp-suggest{ display:flex; gap:6px; flex-wrap:wrap; padding:0 14px 8px; }
#nmcp-suggest button{ background:rgba(155,89,182,.12); border:1px solid rgba(155,89,182,.3); color:#c08fd6;
    font-size:11px; padding:5px 9px; border-radius:14px; cursor:pointer; }
#nmcp-suggest button:hover{ background:rgba(155,89,182,.25); color:#fff; }
#nmcp-input{ display:flex; gap:8px; padding:12px 14px; border-top:1px solid rgba(255,255,255,.1); }
#nmcp-q{ flex:1; resize:none; max-height:110px; background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.15);
    color:#eee; border-radius:10px; padding:9px 11px; font:13px 'Segoe UI',sans-serif; outline:none; }
#nmcp-q:focus{ border-color:#9b59b6; }
#nmcp-send{ background:#9b59b6; border:none; color:#fff; width:42px; border-radius:10px; cursor:pointer; font-size:15px; }
#nmcp-send:hover{ background:#a96bc6; } #nmcp-send:disabled{ opacity:.5; cursor:default; }
.nmcp-spin{ width:13px; height:13px; border:2px solid rgba(255,255,255,.2); border-top-color:#c08fd6; border-radius:50%; display:inline-block; animation:nmcpspin .7s linear infinite; }
@keyframes nmcpspin{ to{ transform:rotate(360deg);} }
@media(max-width:520px){ #nmcp-panel{ width:100vw; } }
</style>

<script>
let _nmcpHist = [];
try { _nmcpHist = JSON.parse(localStorage.getItem('nmcp_hist')||'[]'); } catch(e){ _nmcpHist=[]; }
let _nmcpReady = null, _nmcpBusy = false;

function nmcpEsc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function nmcpFmt(s){ return nmcpEsc(s).replace(/\*\*(.+?)\*\*/g,'<b>$1</b>').replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\n/g,'<br>'); }

function nmcpToggle(){
    const p=document.getElementById('nmcp-panel'); const open=p.classList.toggle('open');
    p.setAttribute('aria-hidden', open?'false':'true');
    if(open){ nmcpRender(); nmcpHealth(); setTimeout(()=>document.getElementById('nmcp-q').focus(),250); }
}
async function nmcpHealth(){
    const s=document.getElementById('nmcp-status');
    if(_nmcpReady===true){ s.textContent='online'; s.style.cssText='background:rgba(46,204,113,.18);color:#2ecc71'; return; }
    try{ const r=await fetch('nm_copilot.php?api=health').then(r=>r.json()); _nmcpReady=!!r.ready;
        if(_nmcpReady){ s.textContent='online'; s.style.cssText='background:rgba(46,204,113,.18);color:#2ecc71'; }
        else { s.textContent='not configured'; s.style.cssText='background:rgba(243,156,18,.18);color:#f39c12'; }
    }catch(e){ s.textContent='offline'; s.style.cssText='background:rgba(231,76,60,.18);color:#e74c3c'; }
}
function nmcpRender(){
    const box=document.getElementById('nmcp-msgs');
    if(!_nmcpHist.length){ box.innerHTML=`<div class="nmcp-empty"><i class="fa-solid fa-wand-magic-sparkles"></i>
        I'm your NEURU expert. Ask about the network (slow links, incidents, device health, who's using bandwidth)
        <b>or</b> how to use the portal — where an option is, how to configure a node, how to build a widget, anything.</div>`; return; }
    box.innerHTML=_nmcpHist.map(m=>{
        if(m.role==='user') return `<div class="nmcp-msg nmcp-user">${nmcpEsc(m.content)}</div>`;
        let ev=''; if(m.evidence&&m.evidence.length) ev=`<div class="nmcp-ev"><div class="h">Evidence</div>${m.evidence.map(e=>`<div>• ${nmcpEsc(typeof e==='string'?e:JSON.stringify(e))}</div>`).join('')}</div>`;
        let dg=''; if(m.diagram) dg=`<div class="nmcp-diag">${nmcpEsc(m.diagram)}</div>`;
        return `<div class="nmcp-msg nmcp-ai">${nmcpFmt(m.content)}${ev}${dg}</div>`;
    }).join('');
    box.scrollTop=box.scrollHeight;
}
function nmcpSave(){ try{ localStorage.setItem('nmcp_hist', JSON.stringify(_nmcpHist.slice(-40))); }catch(e){} }
function nmcpClear(){ _nmcpHist=[]; nmcpSave(); nmcpRender(); }
function nmcpAsk(q){ document.getElementById('nmcp-q').value=q; nmcpSend(); }

async function nmcpSend(){
    if(_nmcpBusy) return;
    const ta=document.getElementById('nmcp-q'); const q=ta.value.trim(); if(!q) return;
    ta.value=''; _nmcpBusy=true; document.getElementById('nmcp-send').disabled=true;
    _nmcpHist.push({role:'user',content:q}); nmcpSave(); nmcpRender();
    const box=document.getElementById('nmcp-msgs');
    const think=document.createElement('div'); think.className='nmcp-think';
    think.innerHTML='<span class="nmcp-spin"></span> Copilot is checking the network…'; box.appendChild(think); box.scrollTop=box.scrollHeight;

    // best-effort page context (selected node if a page exposes one)
    const ctx={ page: location.pathname.replace(/^.*\//,''),
        node_id: (window._nodeId||window.selectedId||null) };
    const hist=_nmcpHist.filter(m=>m.role).map(m=>({role:m.role,content:m.content})).slice(-8);
    try{
        const r=await fetch('nm_copilot.php?api=ask',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({question:q,history:hist,context:ctx})}).then(r=>r.json());
        think.remove();
        if(!r.ok){ _nmcpHist.push({role:'ai',content:'⚠️ '+(r.err||'Copilot error')+(r.hint?('\n\n'+r.hint):'')}); }
        else { _nmcpHist.push({role:'ai',content:r.answer||'(no answer)',evidence:r.evidence||[],diagram:r.diagram||null}); }
    }catch(e){ think.remove(); _nmcpHist.push({role:'ai',content:'⚠️ Request failed.'}); }
    nmcpSave(); nmcpRender(); _nmcpBusy=false; document.getElementById('nmcp-send').disabled=false; ta.focus();
}
// auto-grow textarea
document.addEventListener('input',e=>{ if(e.target&&e.target.id==='nmcp-q'){ e.target.style.height='auto'; e.target.style.height=Math.min(110,e.target.scrollHeight)+'px'; } });
</script>
