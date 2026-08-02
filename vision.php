<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Local Vision "Eye" (vision.php). A HIDDEN iframe inside the AI Commander that
// runs the operator's webcam + face-api.js ENTIRELY IN THE BROWSER: it computes presence
// + attention (are they looking at the screen) and postMessages a tiny state to the cockpit.
// The VIDEO NEVER LEAVES THE MACHINE — only {state,attention} is sent. Identity comes from
// the authenticated session (we already know who is logged in). RBAC: 'autopilotv2'.
// Scoped relaxed CSP (see .htaccess NM_VISION) so face-api/TF.js can load its wasm/workers.
// Needs a SECURE CONTEXT (HTTPS) for the camera — same as voice.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
if (!checkAccess($conn, 'autopilotv2')) { header('Location: /denied_access.php?page=autopilotv2'); exit; }
if (function_exists('session_write_close')) @session_write_close();
$embed = isset($_GET['embed']);
?><!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NEURU · Vision</title>
<style>
  :root{ --cy:#39e6ff; }
  *{box-sizing:border-box} html,body{margin:0;height:100%}
  body{background:#05060e;color:#cfe;font-family:system-ui,Segoe UI,Roboto,sans-serif;overflow:hidden}
  body.embed{background:transparent}
  .wrap{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:10px;text-align:center}
  video{border-radius:10px;border:1px solid rgba(57,230,255,.25);transform:scaleX(-1)}
  body.embed video{ position:fixed;width:2px;height:2px;opacity:0;pointer-events:none }  /* invisible in embed by default */
  body.embed.showcam .wrap{ height:100%;justify-content:flex-start;padding:8px }
  body.embed.showcam video{ position:static;width:100%;height:auto;max-height:78%;opacity:1;pointer-events:auto }
  body.embed.showcam .st{ background:rgba(6,10,22,.6);border-radius:8px;padding:4px 10px;margin-top:6px }
  .st{font-size:12px;letter-spacing:.06em}
  .warn{max-width:360px;background:rgba(255,90,110,.1);border:1px solid rgba(255,90,110,.4);border-radius:12px;padding:12px 14px;font-size:13px;color:#ffd7dd}
</style>
</head><body class="<?php echo $embed?'embed':''; ?>">
<div class="wrap">
  <video id="v" width="240" height="180" autoplay muted playsinline></video>
  <div class="st" id="st">Vision starting…</div>
  <div id="warn" class="warn" style="display:none"></div>
</div>
<script src="/face-api.js"></script>
<script>
(function(){
  var video=document.getElementById('v'), stEl=document.getElementById('st');
  function say(s){ stEl.textContent=s; }
  var lastIdentity='unknown';
  function toParent(state,att){ try{ if(window.parent&&window.parent!==window) window.parent.postMessage({type:'neuru-vision',state:state,attention:att,identity:lastIdentity}, location.origin); }catch(e){} }
  if(!window.isSecureContext){ say('needs HTTPS'); var w=document.getElementById('warn'); w.style.display='block'; w.textContent='🔒 Vision needs HTTPS for the camera. Open NEURU over https://…:8453.'; return; }
  if(!window.faceapi){ say('face engine failed to load'); return; }

  var lastSeen=0, cur='absent', ABSENT_MS=30000, tickT=null, paused=false, idT=null, stopped=false, curStream=null;
  function center(pts){ var x=0,y=0; for(var i=0;i<pts.length;i++){x+=pts[i].x;y+=pts[i].y;} return {x:x/pts.length,y:y/pts.length}; }
  function emit(state,att){ if(state!==cur){ cur=state; say(state.toUpperCase()+(att?(' · '+Math.round(att*100)+'%'):'')); } toParent(state,att); }
  // ── head-gesture detection (nod = approve, shake = deny) from the nose path, size-normalized ──
  var gHist=[], gCool=0;
  function oscill(a){ var c=0,prev=0; for(var i=1;i<a.length;i++){ var d=a[i]-a[i-1]; if(Math.abs(d)<0.03)continue; var s=d>0?1:-1; if(prev&&s!==prev)c++; prev=s; } return c; }
  function trackGesture(now,nx,ny){
    gHist.push({t:now,nx:nx,ny:ny}); gHist=gHist.filter(function(g){return now-g.t<1500;});
    if(now<gCool || gHist.length<7) return null;
    var xs=gHist.map(function(g){return g.nx;}), ys=gHist.map(function(g){return g.ny;});
    var xr=Math.max.apply(null,xs)-Math.min.apply(null,xs), yr=Math.max.apply(null,ys)-Math.min.apply(null,ys);
    var xo=oscill(xs), yo=oscill(ys);
    if(yr>0.28 && yo>=2 && yr>xr*1.3){ gCool=now+2200; gHist=[]; return 'nod'; }
    if(xr>0.45 && xo>=2 && xr>yr*1.3){ gCool=now+2200; gHist=[]; return 'shake'; }
    return null;
  }
  function toGesture(g){ try{ if(window.parent&&window.parent!==window) window.parent.postMessage({type:'neuru-gesture',gesture:g}, location.origin); }catch(e){} say('👋 '+g.toUpperCase()); }

  async function start(){
    say('loading models…');
    try{
      await faceapi.nets.tinyFaceDetector.loadFromUri('/models');
      await faceapi.nets.faceLandmark68Net.loadFromUri('/models');
    }catch(e){ say('model load error'); return; }
    say('requesting camera…');
    var stream;
    try{ stream=await navigator.mediaDevices.getUserMedia({video:{width:320,height:240,facingMode:'user'},audio:false}); }
    catch(e){ say('camera denied'); var w=document.getElementById('warn'); w.style.display='block'; w.textContent='📷 Camera blocked. Allow the camera for presence detection (it stays 100% local).'; toParent('absent',0); return; }
    curStream=stream; if(stopped){ try{ stream.getTracks().forEach(function(t){t.stop();}); }catch(e){} return; }   // toggled off while camera was warming up
    video.srcObject=stream; await video.play().catch(function(){});
    var opts=new faceapi.TinyFaceDetectorOptions({inputSize:160,scoreThreshold:0.45});   // 160 = much lighter on CPU
    // ── face-identity (OPT-IN, CPU-safe): only runs if a face is enrolled; verifies every 6s, paused in calls ──
    var enrolledDesc=null, idBusy=false;
    faceapi.nets.faceRecognitionNet.loadFromUri('/models').catch(function(){});
    fetch('/autopilotv2.php?api=face_get').then(function(r){return r.json();}).then(function(jj){ if(jj&&jj.desc){ enrolledDesc=new Float32Array(jj.desc); } }).catch(function(){});
    async function idCheck(){
      if(paused||idBusy||!enrolledDesc||cur==='absent'||!faceapi.nets.faceRecognitionNet.isLoaded) return;
      idBusy=true;
      try{ var r2=await faceapi.detectSingleFace(video,opts).withFaceLandmarks().withFaceDescriptor();
        if(r2&&r2.descriptor){ var dist=faceapi.euclideanDistance(r2.descriptor,enrolledDesc); lastIdentity=dist<0.5?'you':(dist>0.62?'stranger':'unknown'); }
      }catch(e){} idBusy=false;
    }
    idT=setInterval(idCheck,6000);
    window.__enroll=async function(csrf){ say('enrolling…');
      try{ var r3=await faceapi.detectSingleFace(video,opts).withFaceLandmarks().withFaceDescriptor();
        if(r3&&r3.descriptor){ var arr=Array.prototype.slice.call(r3.descriptor);
          var rr=await fetch('/autopilotv2.php?api=face_enroll',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'desc='+encodeURIComponent(JSON.stringify(arr))+'&csrf='+encodeURIComponent(csrf||'')}).then(function(x){return x.json();});
          if(rr&&rr.ok){ enrolledDesc=r3.descriptor; lastIdentity='you'; say('enrolled ✓'); try{ window.parent.postMessage({type:'neuru-vision-enrolled'},location.origin); }catch(e){} }
          else say('enroll failed'); }
        else say('face not clear — center your face'); }catch(e){ say('enroll error'); }
    };
    say('watching…');
    async function tick(){
      if(stopped) return;                                   // vision toggled off → stop the loop entirely
      if(paused){ tickT=setTimeout(tick,1200); return; }   // paused during a VAPI voice call → free the CPU (no stutter)
      var att=0, present=false;
      try{
        var res=await faceapi.detectSingleFace(video,opts).withFaceLandmarks();
        if(res && res.detection && res.detection.box){
          var box=res.detection.box, lm=res.landmarks;
          // require a reasonably-sized (close-enough) face
          if(box.width > video.videoWidth*0.14){
            present=true; lastSeen=Date.now();
            var le=center(lm.getLeftEye()), re=center(lm.getRightEye()), nose=lm.getNose();
            var noseTip=nose[nose.length-1]||nose[3];
            var eyeMid={x:(le.x+re.x)/2,y:(le.y+re.y)/2}, eyeDist=Math.hypot(re.x-le.x,re.y-le.y)||1;
            var off=Math.abs((noseTip.x-eyeMid.x)/eyeDist);      // ~0 frontal, grows when turned away
            att=Math.max(0,Math.min(1,1-off/0.5));
            // gestures (nose path, normalized by eye distance so it's distance-invariant)
            var gg=trackGesture(Date.now(), noseTip.x/eyeDist, noseTip.y/eyeDist); if(gg) toGesture(gg);
          }
        }
      }catch(e){}
      var now=Date.now();
      if(present){ emit(att>=0.55?'engaged':'passive', att); }
      else if(now-lastSeen>ABSENT_MS){ emit('absent',0); }
      // else: brief blink/turn — hold last state (no flip)
      tickT=setTimeout(tick,600);
    }
    tick();
  }
  start();
  // parent can show/hide the live camera preview (for trust + testing)
  window.addEventListener('message',function(ev){ if(ev.origin!==location.origin)return; var d=ev.data; if(!d||d.type!=='neuru-vision-cmd')return;
    if(d.cmd==='preview'){ document.body.classList.toggle('showcam', !!d.show); }
    else if(d.cmd==='pause'){ paused=true; say('paused · voice call'); }
    else if(d.cmd==='resume'){ paused=false; say('watching…'); }
    else if(d.cmd==='enroll'){ if(window.__enroll) window.__enroll(d.csrf||''); }
    else if(d.cmd==='stop'){ stopVision(); }
  });
  function stopVision(){ stopped=true; paused=true; if(tickT){clearTimeout(tickT);tickT=null;} if(idT){clearInterval(idT);idT=null;}
    try{ var s=curStream||(video&&video.srcObject); if(s)s.getTracks().forEach(function(t){t.stop();}); }catch(e){}
    try{ if(video)video.srcObject=null; }catch(e){} say('camera off'); }
  window.addEventListener('beforeunload',stopVision);
})();
</script>
</body></html>
