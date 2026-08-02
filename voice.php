<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Commander V2.0 VOICE popup (voice.php). Opened as a child window from the
// cockpit's 🎙 Talk button. Self-hosted VAPI Web SDK (/vapi-web.js → window.vapiSDK)
// runs a WebRTC voice call with the customer's VAPI assistant, whose ask_neuru tool calls
// autopilotv2_vapi.php → the same NEURU brain as the text chat. RBAC: 'autopilotv2'.
// This page gets a SCOPED relaxed CSP (see .htaccess NM_VOICE) so Daily/VAPI can connect.
// Mic needs a SECURE CONTEXT (HTTPS) — handled with a clear message if absent.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_vapi.php');

if (!checkAccess($conn, 'autopilotv2')) { header('Location: /denied_access.php?page=autopilotv2'); exit; }
if (function_exists('session_write_close')) @session_write_close();

$cfg = nm_vapi_public_cfg($conn);
$configured = nm_vapi_configured($conn);
$pub = htmlspecialchars($cfg['public_key'], ENT_QUOTES);
$asst = htmlspecialchars($cfg['assistant_id'], ENT_QUOTES);
$embed = isset($_GET['embed']);   // embedded (iframe) inside the Commander → transparent, compact, posts events to parent
?><!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NEURU · Voice</title>
<style>
  :root{ --cy:#39e6ff; --bg:#05060e; --pn:rgba(10,16,30,.55); --br:rgba(57,230,255,.18); }
  *{box-sizing:border-box} html,body{margin:0;height:100%}
  body{background:var(--bg);color:#dbe6f5;font-family:system-ui,Segoe UI,Roboto,sans-serif;overflow:hidden;
       display:flex;flex-direction:column;align-items:center;justify-content:center;gap:22px;text-align:center;padding:24px}
  .orb{position:relative;width:190px;height:190px;border-radius:50%;display:grid;place-items:center;
       background:radial-gradient(circle at 50% 40%,rgba(57,230,255,.28),rgba(57,230,255,.03) 60%,transparent 70%);
       transition:transform .12s ease}
  .orb::before{content:"";position:absolute;inset:-14px;border-radius:50%;border:1px solid var(--br);
       box-shadow:0 0 60px rgba(57,230,255,.25) inset,0 0 40px rgba(57,230,255,.15)}
  .core{width:96px;height:96px;border-radius:50%;background:radial-gradient(circle at 45% 35%,#8bf3ff,#0aa4c9 55%,#053043);
       box-shadow:0 0 40px rgba(57,230,255,.6);animation:breathe 3.4s ease-in-out infinite}
  @keyframes breathe{0%,100%{transform:scale(.94);opacity:.9}50%{transform:scale(1.04);opacity:1}}
  .ring{position:absolute;inset:0;border-radius:50%;border:2px solid transparent}
  .listening .ring{border-color:rgba(57,230,255,.5);animation:spin 2.4s linear infinite}
  .speaking .core{animation:breathe 1.1s ease-in-out infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  h1{font-size:15px;letter-spacing:.22em;text-transform:uppercase;color:var(--cy);margin:0;font-weight:600}
  .status{font-size:13px;color:#7fa6c8;min-height:18px}
  .btns{display:flex;gap:12px}
  button{font:inherit;cursor:pointer;border-radius:999px;padding:12px 26px;font-weight:600;letter-spacing:.03em;
       border:1px solid var(--br);background:var(--pn);color:#dbe6f5;transition:.15s}
  button:hover{border-color:var(--cy);box-shadow:0 0 16px rgba(57,230,255,.25)}
  button.go{background:linear-gradient(180deg,#0bbfe0,#067a95);border-color:transparent;color:#02121a}
  button.stop{background:linear-gradient(180deg,#ff5a6e,#b02334);border-color:transparent;color:#fff}
  button:disabled{opacity:.4;cursor:not-allowed;box-shadow:none}
  #tx{position:absolute;left:0;right:0;bottom:0;max-height:34vh;overflow:auto;padding:14px 18px;
      background:linear-gradient(0deg,rgba(4,6,14,.92),transparent);display:flex;flex-direction:column;gap:6px;font-size:13px}
  .line{max-width:80%;padding:7px 12px;border-radius:12px;line-height:1.35}
  .line.u{align-self:flex-end;background:rgba(57,230,255,.14);border:1px solid var(--br)}
  .line.a{align-self:flex-start;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}
  .warn{max-width:460px;background:rgba(255,90,110,.1);border:1px solid rgba(255,90,110,.4);
        border-radius:14px;padding:18px 20px;font-size:14px;line-height:1.5;color:#ffd7dd}
  .warn code{background:rgba(0,0,0,.4);padding:2px 6px;border-radius:5px;color:#9fe}
  /* hide the SDK's default floating widget button — we drive the call ourselves */
  #vapi-support-btn,.vapi-btn,[id^="vapi"]{display:none!important}
  a.mini{color:#7fa6c8;font-size:12px;text-decoration:none;border-bottom:1px dotted #456}
  /* ── futuristic voice control: a holographic mic core ── */
  .vhud{ display:flex; align-items:center; gap:18px; padding:12px 18px; border-radius:18px;
         background:linear-gradient(180deg,rgba(12,20,38,.5),rgba(8,12,26,.32)); border:1px solid var(--br);
         box-shadow:0 0 0 1px rgba(57,230,255,.05), 0 8px 40px rgba(0,0,0,.35); backdrop-filter:blur(9px); -webkit-backdrop-filter:blur(9px); }
  .miccore{ position:relative; width:74px; height:74px; border:0; padding:0; background:transparent; cursor:pointer; flex:0 0 auto; }
  .miccore:disabled{ cursor:default; }
  .mc-halo{ position:absolute; inset:-12px; border-radius:50%; background:radial-gradient(circle,rgba(57,230,255,.35),transparent 68%); filter:blur(7px); opacity:.7; transition:opacity .25s; }
  .mc-ring{ position:absolute; inset:0; border-radius:50%; border:1.5px solid rgba(57,230,255,.5); box-shadow:0 0 18px rgba(57,230,255,.3) inset; }
  .mc-ring.mc-r2{ inset:-9px; border-color:rgba(57,230,255,.18); border-top-color:rgba(57,230,255,.75); animation:mcspin 7s linear infinite; }
  .mc-ico{ position:absolute; inset:15px; border-radius:50%; display:grid; place-items:center;
           background:radial-gradient(circle at 45% 34%,#8bf3ff,#0aa4c9 58%,#053043); box-shadow:0 0 26px rgba(57,230,255,.5); color:#02131b; }
  .mc-ico svg{ width:26px; height:26px; }
  .miccore:hover .mc-halo{ opacity:1 } .miccore:hover .mc-ico{ box-shadow:0 0 36px rgba(57,230,255,.85) }
  @keyframes mcspin{ to{ transform:rotate(360deg) } }
  @keyframes mcbreathe{ 0%,100%{ transform:scale(.95) } 50%{ transform:scale(1.07) } }
  @keyframes mcpulse{ 0%{ transform:scale(1); opacity:.65 } 100%{ transform:scale(1.85); opacity:0 } }
  body.incall .mc-ico{ animation:mcbreathe 1.4s ease-in-out infinite }
  body.incall .miccore::after{ content:''; position:absolute; inset:0; border-radius:50%; border:2px solid rgba(57,230,255,.55); animation:mcpulse 1.7s ease-out infinite }
  body.incall .mc-halo{ opacity:1; background:radial-gradient(circle,rgba(57,230,255,.5),transparent 66%) }
  .vmeta{ display:flex; flex-direction:column; gap:5px; align-items:flex-start; text-align:left; }
  .vmeta .status{ font-size:12px; letter-spacing:.16em; text-transform:uppercase; color:var(--cy); text-shadow:0 0 12px rgba(57,230,255,.5); min-height:16px; }
  .vhint{ font-size:11px; color:#6f8db0; letter-spacing:.02em; }
  .endbtn{ margin-top:2px; display:inline-flex; align-items:center; gap:7px; padding:6px 14px; border-radius:999px;
           background:rgba(255,60,90,.1); border:1px solid rgba(255,90,110,.38); color:#ffb3bd; font:inherit; font-size:12px; cursor:pointer; transition:.15s; }
  .endbtn:hover:not(:disabled){ background:rgba(255,60,90,.22); box-shadow:0 0 14px rgba(255,90,110,.3) }
  .endbtn:disabled{ opacity:.35; cursor:not-allowed }
  .endbtn .sq{ width:8px; height:8px; background:currentColor; border-radius:2px }
  .chip{ padding:7px 14px; border-radius:999px; background:var(--pn); border:1px solid var(--br); color:#cfe; font:inherit; font-size:12px; cursor:pointer; }
  .chip:hover{ border-color:var(--cy) }
  .chip-sel{ max-width:230px; font-size:11px; padding:7px 10px; }
  /* EMBED mode: transparent, compact control docked at the bottom-center of the WebGL core.
     The parent Commander paints the aurora, so we hide our own orb + full transcript. */
  body.embed{background:transparent;height:auto;min-height:100%;justify-content:flex-end;gap:10px;padding:12px}
  body.embed .orb,body.embed h1{display:none}
  body.embed #tx{position:static;max-height:22vh;background:transparent;padding:6px 4px}
  body.embed .btns button{padding:9px 18px}
</style>
</head><body class="<?php echo $embed ? 'embed' : ''; ?>">
<?php if (!$configured): ?>
  <div class="warn" style="background:rgba(57,230,255,.08);border-color:var(--br);color:#cfe">
    <strong>Voice is not configured yet.</strong><br>
    Add your VAPI <b>public key</b> + <b>assistant id</b> in the NEURU Commander cockpit (Voice card) and enable it.
  </div>
<?php else: ?>
  <h1>NEURU Voice</h1>
  <div id="orb" class="orb"><div class="ring"></div><div class="core"></div></div>
  <div class="vhud">
    <button id="go" class="miccore" title="Start talking">
      <span class="mc-halo"></span><span class="mc-ring"></span><span class="mc-ring mc-r2"></span>
      <span class="mc-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/></svg></span>
    </button>
    <div class="vmeta">
      <div class="status" id="status">STANDBY</div>
      <div class="vhint" id="vhint">Tap the core to speak</div>
      <button id="end" class="endbtn" disabled><span class="sq"></span> End call</button>
    </div>
  </div>
  <div id="micctl" style="display:none;align-items:center;gap:10px;margin-top:4px">
    <button id="mute" class="chip">🔊 Mic ON</button>
    <select id="micsel" class="vin chip-sel"></select>
  </div>
  <div id="secwarn" class="warn" style="display:none"></div>
  <div id="tx"></div>

  <script src="/vapi-web.js"></script>
  <script>
    (function(){
      var PUB="<?php echo $pub; ?>", ASST="<?php echo $asst; ?>";
      var orb=document.getElementById('orb'), statusEl=document.getElementById('status'),
          go=document.getElementById('go'), end=document.getElementById('end'), tx=document.getElementById('tx');
      function setStatus(s){ statusEl.textContent=s; }
      function line(role,text){ var d=document.createElement('div'); d.className='line '+(role==='user'?'u':'a'); d.textContent=text; tx.appendChild(d); tx.scrollTop=tx.scrollHeight; }

      // Mic needs a secure context (HTTPS or localhost). Fail loud + clear (the #1 gotcha).
      if(!window.isSecureContext){
        go.disabled=true;
        var w=document.getElementById('secwarn'); w.style.display='block';
        w.innerHTML="🔒 <b>Voice needs HTTPS.</b> Your browser only allows the microphone on a secure origin. "+
          "Open NEURU over HTTPS — e.g. <code>https://"+location.hostname+":8453</code> — then try again.";
        setStatus("Microphone blocked (not a secure context).");
        return;
      }
      if(!window.vapiSDK){ setStatus("Voice SDK failed to load."); go.disabled=true; return; }

      // Legible error text out of whatever shape VAPI/Daily throws (never "[object Object]").
      function errStr(e){
        try{
          if(!e) return 'unknown';
          if(typeof e==='string') return e;
          if(e.message) return e.message;
          if(e.errorMsg) return e.errorMsg;
          if(e.error){ return (typeof e.error==='string')?e.error:(e.error.message||e.error.msg||JSON.stringify(e.error)); }
          if(e.response){ return (typeof e.response==='string')?e.response:JSON.stringify(e.response); }
          if(e.stage) return 'failed at '+e.stage;
          return JSON.stringify(e);
        }catch(_){ return 'unknown error'; }
      }
      function showErr(e){
        var msg=errStr(e); setStatus("Error: "+msg);
        // the #1 cause: the assistant isn't provisioned yet (id is invalid / not found)
        if(/assistant|not found|400|invalid|does not exist/i.test(msg)){
          var w=document.getElementById('secwarn'); w.style.display='block';
          w.innerHTML="⚠ VAPI couldn't start this assistant. In the cockpit’s <b>Voice</b> tab, clear the "+
            "<i>Assistant ID</i> field and click <b>Auto-provision assistant</b> — NEURU builds it for you — then try again.";
        }
        console.error('[NEURU voice]', e);
      }
      // mic controls: VAPI/Daily sometimes start MUTED, or the browser grabs a silent input device —
      // both make the bot talk while hearing pure silence (VAPI ends with "silence-timed-out"). We
      // force-unmute on connect, expose a Mute toggle, and a device picker wired to the live Daily call.
      var micctl=document.getElementById('micctl'), muteBtn=document.getElementById('mute'), micSel=document.getElementById('micsel'), muted=false;
      function dailyCO(){ try{ return vapi&&vapi.getDailyCallObject&&vapi.getDailyCallObject(); }catch(e){ return null; } }
      function setMuted(m){ muted=m; try{ if(vapi&&vapi.setMuted) vapi.setMuted(m); }catch(e){} muteBtn.textContent=m?'🔇 Muted':'🔊 Mic ON'; muteBtn.style.opacity=m?0.6:1; }
      async function populateMics(){ try{ var d=await navigator.mediaDevices.enumerateDevices(); var ins=d.filter(function(x){return x.kind==='audioinput';}); micSel.innerHTML=ins.map(function(x,i){return '<option value="'+x.deviceId+'">'+(x.label||('Microphone '+(i+1)))+'</option>';}).join(''); }catch(e){} }
      async function applyDevice(id){ var co=dailyCO(); try{ if(co&&co.setInputDevicesAsync) await co.setInputDevicesAsync({audioDeviceId:id}); }catch(e){} }
      muteBtn.onclick=function(){ setMuted(!muted); if(active) setStatus(muted?'Mic muted — tap 🔊 to talk.':'Listening…'); };
      micSel.onchange=function(){ applyDevice(micSel.value); setStatus('Switched microphone.'); };
      // bridge voice events up to the Commander so the WebGL neural core paints the reactive aurora
      function toParent(event,value){ try{ if(window.parent&&window.parent!==window) window.parent.postMessage({type:'neuru-voice',event:event,value:value}, location.origin); }catch(e){} }
      var vapi=null, active=false;
      function ensure(){
        if(vapi) return vapi;
        try{ vapi=window.vapiSDK.run({ apiKey:PUB, assistant:ASST }); }catch(e){ showErr(e); return null; }
        if(!vapi||!vapi.on){ setStatus("Voice SDK not ready."); return null; }
        vapi.on('call-start', function(){ active=true; go.disabled=true; end.disabled=false; orb.classList.add('listening'); document.body.classList.add('incall'); var h=document.getElementById('vhint'); if(h)h.style.display='none'; setStatus("Connected — speak now."); setMuted(false); micctl.style.display='flex'; populateMics(); toParent('call-start'); });
        vapi.on('call-end',   function(){ active=false; go.disabled=false; end.disabled=true; orb.classList.remove('listening','speaking'); document.body.classList.remove('incall'); var h=document.getElementById('vhint'); if(h)h.style.display=''; micctl.style.display='none'; setStatus("Call ended."); toParent('call-end'); });
        vapi.on('speech-start', function(){ orb.classList.add('speaking'); setStatus("NEURU is speaking…"); toParent('speech-start'); });
        vapi.on('speech-end',   function(){ orb.classList.remove('speaking'); if(active) setStatus("Listening…"); toParent('speech-end'); });
        vapi.on('volume-level', function(v){ orb.style.transform='scale('+(1+Math.min(0.18,(v||0)*0.4))+')'; toParent('volume', v||0); });
        vapi.on('message', function(m){
          if(!m||m.type!=='transcript') return;
          if(m.transcriptType==='final'){ line(m.role, m.transcript); toParent('transcript',{role:m.role,text:m.transcript}); }
          // forward that the OPERATOR is mid-utterance so the Commander won't let an alert interrupt (barge-in guard)
          else if(m.transcriptType==='partial' && m.role==='user'){ toParent('user-speaking'); }
        });
        vapi.on('error', showErr);
        return vapi;
      }
      // REVERSE channel: the Commander drives this iframe — speak an alert line (vapi.say) or toggle the call.
      // vapi.say() bypasses the LLM, so proactive narration NEVER changes how VAPI converses with the operator.
      window.addEventListener('message', function(ev){
        if(ev.origin!==location.origin) return;
        var d=ev.data; if(!d||d.type!=='neuru-voice-cmd') return;
        if(d.cmd==='say'){
          var txt=(''+(d.text||'')).slice(0,300); if(!txt) return;
          if(!active) return;   // no VAPI voice channel unless a call is live (voice = VAPI only, never local TTS)
          try{ if(vapi&&vapi.say){ vapi.say(txt); } else if(vapi&&vapi.send){ vapi.send({type:'add-message',message:{role:'assistant',content:txt}}); } }catch(e){}
        } else if(d.cmd==='toggle-call'){
          if(active){ try{ vapi&&vapi.stop(); }catch(e){} }
          else { var v=ensure(); if(v){ setStatus("Connecting… (allow the microphone)"); try{ v.start(ASST); }catch(e){ showErr(e); } } }
        }
      });
      go.onclick=function(){ var v=ensure(); if(!v) return; setStatus("Connecting… (allow the microphone)"); try{ v.start(ASST); }catch(e){ showErr(e); } };
      end.onclick=function(){ if(vapi){ try{ vapi.stop(); }catch(e){} } };
      window.addEventListener('beforeunload', function(){ if(vapi&&active){ try{ vapi.stop(); }catch(e){} } });
    })();
  </script>
<?php endif; ?>
</body></html>
