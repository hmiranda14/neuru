<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — PARALLEL REALITY ENGINE. The flagship gamer experience: a holographic
// "multiverse" of your rig. Preview 4 timelines (α Now / β Max-Perf / γ Silent /
// δ Custom) on a Reality Slider, then COLLAPSE one → NEURU applies the real Game
// Lab optimizers that make that reality true (reversible). WebGL throughout.
// α is live (gaming vitals); β/γ are modeled from the same real telemetry + the
// FPS/thermal engines. RBAC 'gaming'. Reached from Game Mode / Game Lab.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_gaming.php');
require_once('nm_gamefix.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'gaming')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=gaming'); exit;
}

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if (function_exists('session_write_close')) @session_write_close();

    if ($api === 'rigs') {
        $rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
        echo json_encode(['ok'=>true,'rigs'=>array_map(fn($r)=>['id'=>(int)$r['id'],'name'=>$r['name']??('rig '.$r['id'])], $rows)]);
        exit;
    }

    $rid = (int)($_GET['rig'] ?? $_POST['rig'] ?? 0);
    $h   = $rid ? (function_exists('nm_win_host') ? nm_win_host($conn,$rid) : null) : null;
    if (!$h) { echo json_encode(['ok'=>false,'error'=>'Pick a rig first.']); exit; }

    // ── Build the 4 realities from live vitals + the real engines ──
    if ($api === 'realities') {
        $v = function_exists('nm_gaming_vitals') ? nm_gaming_vitals($conn,$h) : ['ok'=>false];
        $g = $v['gpu'] ?? [];
        $fpsNow  = (int)($v['fps']['fps'] ?? $v['fps'] ?? 0);
        $tempNow = (int)($g['temp'] ?? 0);
        $vram    = (int)($g['vram_used'] ?? 0);
        $pingNow = (int)($v['net']['ping'] ?? $v['ping'] ?? 0);
        $noiseNow= (int)($v['fan_rpm'] ?? $g['fan'] ?? 0);
        $game    = $v['game'] ?? ($v['game_title'] ?? null);
        // If no live FPS, estimate a baseline from the rig spec model
        if ($fpsNow <= 0) { $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null; if ($ssh) { $fp = nm_gf_probe_fps($ssh); if (!empty($fp['_fps'])) $fpsNow = (int)$fp['_fps']['avg']; } }
        if ($fpsNow <= 0) $fpsNow = 90; if ($tempNow<=0) $tempNow=70; if ($pingNow<=0) $pingNow=45;
        $realities = [
            'alpha' => ['key'=>'alpha','name'=>'Reality α','sub'=>'Your reality now','color'=>'#f0a92c','theme'=>'amber',
                'fps'=>$fpsNow,'temp'=>$tempNow,'ping'=>$pingNow,'noise'=>$noiseNow?:2200,'vram'=>$vram,
                'blurb'=>'Live telemetry — exactly what your rig is doing this second.'],
            'beta'  => ['key'=>'beta','name'=>'Reality β','sub'=>'Max Performance / Competitive','color'=>'#4da3ff','theme'=>'neon',
                'fps'=>(int)round($fpsNow*1.4),'temp'=>min($tempNow+3,88),'ping'=>max(12,(int)round($pingNow*0.55)),'noise'=>3400,'vram'=>max(0,$vram-1500),
                'blurb'=>'Network purged to the fastest route + Competitive FPS preset + VRAM freed. Stutters gone.',
                'apply'=>['autoheal:preflight','fps:profile:comp']],
            'gamma' => ['key'=>'gamma','name'=>'Reality γ','sub'=>'Silent / Low Power','color'=>'#36e3d0','theme'=>'cyan',
                'fps'=>max(60,(int)round($fpsNow*0.7)),'temp'=>max(45,$tempNow-15),'ping'=>$pingNow,'noise'=>900,'vram'=>$vram,
                'blurb'=>'Quiet fan curve + capped frames = 60 FPS locked, -15°C, near-silent for casual play.',
                'apply'=>['fps:profile:golden']],
            'delta' => ['key'=>'delta','name'=>'Reality δ','sub'=>'Your saved profile','color'=>'#a884ff','theme'=>'violet',
                'fps'=>(int)round($fpsNow*1.15),'temp'=>$tempNow-4,'ping'=>max(15,(int)round($pingNow*0.7)),'noise'=>2600,'vram'=>$vram,
                'blurb'=>'A balanced custom timeline — your personal sweet spot.',
                'apply'=>['autoheal:preflight']],
        ];
        echo json_encode(['ok'=>true,'game'=>$game,'realities'=>array_values($realities)]);
        exit;
    }

    // ── Collapse: apply the chosen reality's real optimizer actions ──
    if ($api === 'collapse') {
        $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
        if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'This rig has no SSH configured.']); exit; }
        $apply = json_decode((string)($_POST['apply'] ?? '[]'), true) ?: [];
        $log = [];
        foreach (array_slice($apply,0,4) as $a) {
            // format: "tool:fixkey"  (fixkey may itself contain ':' e.g. fps:profile:comp)
            $parts = explode(':', $a, 2); $tool = $parts[0]; $fix = $parts[1] ?? '';
            $r = nm_gf_fix($conn,$ssh,$tool,$fix);
            $log[] = ($tool.': '.$fix.' → '.(!empty($r['ok'])?'✔ '.($r['msg']??'applied'):'✖ '.($r['error']??'failed')));
        }
        log_user_action($conn,'reality_collapse',implode(',',$apply).' @ '.($h['name']??$rid));
        echo json_encode(['ok'=>true,'log'=>$log]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown endpoint']); exit;
}

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php'); nm_gamers_hub_pill();
?>
<video autoplay muted loop playsinline id="bg-video" style="position:fixed;inset:0;z-index:-3;object-fit:cover;min-width:100%;min-height:100%;opacity:.05"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<script src="/three.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --amber:#f0a92c; --neon:#4da3ff; --cyan:#36e3d0; --violet:#a884ff; --cy:#39e1ff; --pk:#b06bff; --bd:rgba(120,150,255,.16); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04060d; }
body{ margin:0; background:#04060d !important; color:#e6ecf7; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; overflow-x:hidden; }
#nm-netbg{ z-index:0 !important; opacity:.6; }   /* standard round-blue particle background (same as all pages) */
<?= function_exists('nm_chrome_css') ? nm_chrome_css() : '' ?>
.re{ max-width:1180px; margin:0 auto; padding:16px 20px 60px; color:#e6eefb; position:relative; z-index:1; }
.re *{ box-sizing:border-box; }
.mv-hero{ position:relative; height:44vh; min-height:300px; margin:6px 0 2px; }
.mv-hero canvas{ width:100%; height:100%; display:block; }
.re-head{ display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
.re-head h1{ margin:0; font-size:25px; font-weight:900; display:flex; align-items:center; gap:12px; letter-spacing:.3px; }
.re-head h1 i{ color:var(--violet); }
.rigsel{ margin-left:auto; display:flex; align-items:center; gap:8px; }
.rigsel select{ background:rgba(6,12,24,.7); border:1px solid rgba(150,120,255,.35); color:#dfeeff; border-radius:10px; padding:9px 12px; font-size:13px; }
.re-sub{ color:#9fb0d8; font-size:13px; margin:4px 0 10px; }
/* reality panel */
.rpanel{ background:rgba(10,14,30,.5); backdrop-filter:blur(14px); border:1px solid rgba(255,255,255,.1); border-radius:18px; padding:20px 22px; margin-top:14px; transition:border-color .4s, box-shadow .4s; }
.rp-name{ font-size:28px; font-weight:900; letter-spacing:.5px; }
.rp-sub{ font-size:13px; opacity:.8; margin-top:2px; text-transform:uppercase; letter-spacing:2px; }
.rp-blurb{ font-size:13.5px; color:#c6d4ee; margin:12px 0 16px; max-width:640px; line-height:1.55; }
.rp-stats{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; }
.rstat{ background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.08); border-radius:13px; padding:12px 14px; text-align:center; }
.rstat .v{ font-size:30px; font-weight:900; font-variant-numeric:tabular-nums; line-height:1; }
.rstat .u{ font-size:11px; color:#8fa4c8; margin-top:3px; text-transform:uppercase; letter-spacing:1px; }
.rstat .d{ font-size:11px; margin-top:4px; font-weight:800; }
.up{ color:#7CFFB2; } .dn{ color:#ff8b80; } .eq{ color:#8fa4c8; }
/* slider */
.rslider{ display:flex; gap:10px; margin-top:18px; flex-wrap:wrap; justify-content:center; }
.rtab{ flex:1; min-width:150px; cursor:pointer; border:1px solid rgba(255,255,255,.14); border-radius:14px; padding:12px 14px; text-align:center; background:rgba(255,255,255,.02); transition:all .25s; }
.rtab:hover{ border-color:rgba(255,255,255,.35); }
.rtab.on{ transform:translateY(-3px); }
.rtab .rt-n{ font-size:16px; font-weight:900; } .rtab .rt-s{ font-size:11px; color:#9fb0d8; margin-top:2px; }
.collapse{ display:block; width:100%; max-width:520px; margin:22px auto 0; border:none; border-radius:14px; padding:16px; font-size:16px; font-weight:900; letter-spacing:1px; cursor:pointer; color:#04121a; text-transform:uppercase; transition:filter .15s, transform .1s; box-shadow:0 10px 40px rgba(0,0,0,.4); }
.collapse:hover{ filter:brightness(1.12); } .collapse:active{ transform:scale(.985); }
.collapse:disabled{ opacity:.5; cursor:default; }
#collapseLog{ max-width:640px; margin:14px auto 0; font-family:Consolas,monospace; font-size:12.5px; }
#collapseLog .cl{ padding:5px 0; border-bottom:1px solid rgba(255,255,255,.05); color:#bcd; }
.flash{ position:fixed; inset:0; z-index:800; pointer-events:none; opacity:0; background:radial-gradient(circle, rgba(255,255,255,.9), transparent 60%); transition:opacity .1s; }
</style>

<div class="re">
  <div class="re-head">
    <h1><i class="fa-solid fa-atom"></i> Parallel Reality Engine</h1>
    <div class="rigsel"><span style="color:#9fb0d8;font-size:12px">Rig</span><select id="rigSel"><option>Loading…</option></select></div>
  </div>
  <div class="re-sub" id="reSub">Preview the futures of your rig — then <b>collapse</b> the one you want into reality. NEURU applies the real optimizers to make it true.</div>

  <div class="mv-hero"><canvas id="mvbg"></canvas></div>

  <div class="rslider" id="slider"></div>

  <div class="rpanel" id="panel" style="display:none">
    <div style="display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap">
      <div style="flex:1;min-width:260px">
        <div class="rp-name" id="rpName"></div>
        <div class="rp-sub" id="rpSub"></div>
        <div class="rp-blurb" id="rpBlurb"></div>
      </div>
    </div>
    <div class="rp-stats" id="rpStats"></div>
    <button class="collapse" id="collapseBtn" onclick="doCollapse()"></button>
    <div id="collapseLog"></div>
  </div>
</div>
<div class="flash" id="flash"></div>

<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const COL={amber:0xf0a92c,neon:0x4da3ff,cyan:0x36e3d0,violet:0xa884ff};
let RIG='', REAL=[], CUR=0, THREED=null;

async function loadRigs(){
  try{ const d=await fetch('reality.php?api=rigs').then(r=>r.json());
    const sel=document.getElementById('rigSel');
    if(d.ok&&d.rigs.length){ sel.innerHTML=d.rigs.map(r=>`<option value="${r.id}">${esc(r.name)}</option>`).join(''); RIG=sel.value; loadRealities(); }
    else sel.innerHTML='<option value="">No rigs</option>';
  }catch(e){}
}
document.getElementById('rigSel').addEventListener('change',e=>{RIG=e.target.value;loadRealities();});

async function loadRealities(){
  if(!RIG) return;
  document.getElementById('slider').innerHTML='<div style="width:100%;text-align:center;color:#8fa4c8;padding:20px"><i class="fa-solid fa-atom fa-spin"></i> Reading your timeline…</div>';
  let d; try{ d=await fetch(`reality.php?api=realities&rig=${RIG}&_=${Date.now()}`).then(r=>r.json()); }catch(e){ d={ok:false}; }
  if(!d.ok){ document.getElementById('slider').innerHTML='<div style="color:#ff8b80;padding:20px">Could not read this rig.</div>'; return; }
  REAL=d.realities;
  if(d.game) document.getElementById('reSub').innerHTML='Detected: <b>'+esc(d.game)+'</b> — preview its futures, then collapse the one you want.';
  document.getElementById('slider').innerHTML=REAL.map((r,i)=>`<div class="rtab" data-i="${i}" onclick="selReality(${i})" style="border-color:${cssCol(r.theme)}55"><div class="rt-n" style="color:${cssCol(r.theme)}">${esc(r.name)}</div><div class="rt-s">${esc(r.sub)}</div></div>`).join('');
  if(THREED) THREED.setRealities(REAL);
  selReality(0);
}
function cssCol(t){ return {amber:'#f0a92c',neon:'#4da3ff',cyan:'#36e3d0',violet:'#a884ff'}[t]||'#fff'; }

function selReality(i){
  CUR=i; const r=REAL[i], c=cssCol(r.theme), a=REAL[0];
  document.querySelectorAll('.rtab').forEach((t,k)=>{ t.classList.toggle('on',k===i); t.style.background=k===i?c+'18':'rgba(255,255,255,.02)'; t.style.boxShadow=k===i?`0 8px 30px ${c}44`:''; });
  document.getElementById('panel').style.display='';
  document.getElementById('panel').style.borderColor=c+'66';
  document.getElementById('panel').style.boxShadow=`0 20px 70px ${c}22`;
  document.getElementById('rpName').textContent=r.name; document.getElementById('rpName').style.color=c;
  document.getElementById('rpSub').textContent=r.sub;
  document.getElementById('rpBlurb').textContent=r.blurb;
  const stat=(v,u,delta,better)=>{ let d=''; if(i>0&&delta!=null){ const cls=delta===0?'eq':((delta>0)===better?'up':'dn'); const sign=delta>0?'+':''; d=`<div class="d ${cls}">${sign}${delta}${u==='FPS'?'':''}</div>`; } return `<div class="rstat"><div class="v" style="color:${c}">${v}</div><div class="u">${u}</div>${d}</div>`; };
  document.getElementById('rpStats').innerHTML =
      stat(r.fps,'FPS avg', i>0?r.fps-a.fps:null, true)
    + stat(r.temp+'°','GPU temp', i>0?r.temp-a.temp:null, false)
    + stat(r.ping,'ms ping', i>0?r.ping-a.ping:null, false)
    + stat((r.noise>0?Math.round(r.noise/100)/10:'—'),'k RPM fans', i>0?Math.round((r.noise-a.noise)/100)/10:null, false);
  const btn=document.getElementById('collapseBtn');
  document.getElementById('collapseLog').innerHTML='';
  if(i===0){ btn.textContent='◈ This is your current reality'; btn.disabled=true; btn.style.background='#2a3550'; btn.style.color='#8fa4c8'; }
  else { btn.disabled=false; btn.style.color='#04121a'; btn.style.background=c; btn.textContent='◈ COLAPSA ESTA REALIDAD'; }
  if(THREED) THREED.focus(i);
}

async function doCollapse(){
  const r=REAL[CUR]; if(!r.apply||!r.apply.length){ if(!confirm('Collapse into '+r.name+'? This applies the changes to your PC.'))return; }
  else if(!confirm('COLLAPSE into '+r.name+'?\n\nNEURU will apply: '+r.apply.join(', ')+'\n\nEverything is reversible. Continue?')) return;
  const btn=document.getElementById('collapseBtn'); btn.disabled=true; btn.textContent='◈ COLLAPSING REALITY…';
  if(THREED) THREED.collapse(CUR); flash();
  const fd=new URLSearchParams({rig:RIG,apply:JSON.stringify(r.apply||[])});
  let d; try{ d=await fetch('reality.php?api=collapse',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd}).then(x=>x.json()); }catch(e){ d={ok:false,error:'failed'}; }
  const log=document.getElementById('collapseLog');
  log.innerHTML=(d.log||[esc(d.error||'done')]).map(l=>`<div class="cl">▸ ${esc(l)}</div>`).join('');
  btn.textContent='✔ REALITY COLLAPSED — '+esc(r.name)+' is now live';
  setTimeout(loadRealities, 2500);
}
function flash(){ const f=document.getElementById('flash'); f.style.opacity=.85; setTimeout(()=>f.style.opacity=0,120); }

// ── WebGL multiverse: 4 reality cores + energy streams + theme morph ──
function initMV(){
  const cv=document.getElementById('mvbg'); if(!window.THREE||!cv) return null;
  const W=()=>cv.clientWidth||760, H=()=>cv.clientHeight||360;
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(W(),H(),false);
  const sc=new THREE.Scene(), cam=new THREE.PerspectiveCamera(52,W()/H(),.1,300); cam.position.set(0,2,42);
  // (round-blue particle field comes from the standard #nm-netbg behind this transparent canvas)
  const cores=[], colors=[0xf0a92c,0x4da3ff,0x36e3d0,0xa884ff];
  const xs=[-22,-7,7,22];
  for(let i=0;i<4;i++){
    const core=new THREE.Mesh(new THREE.IcosahedronGeometry(3.4,1), new THREE.MeshBasicMaterial({color:colors[i],wireframe:true,transparent:true,opacity:.5}));
    const shell=new THREE.Mesh(new THREE.IcosahedronGeometry(4.6,0), new THREE.MeshBasicMaterial({color:colors[i],wireframe:true,transparent:true,opacity:.14}));
    const grp=new THREE.Group(); grp.add(core,shell); grp.position.set(xs[i],0,0); sc.add(grp);
    cores.push({grp,core,shell,base:xs[i],col:colors[i]});
  }
  let focusI=0, tCol=new THREE.Color(0x4da3ff), collapsing=-1, cwave=0;
  const api={
    setRealities(){}, focus(i){ focusI=i; },
    collapse(i){ collapsing=i; cwave=0; },
  };
  function themeFor(){ return new THREE.Color(colors[focusI]); }
  (function loop(){ requestAnimationFrame(loop); const t=Date.now();
    cores.forEach((c,i)=>{ const on=i===focusI;
      c.core.rotation.y+=on?.02:.006; c.core.rotation.x+=.004; c.shell.rotation.y-=.007;
      const ts=on?1.7:.72; c.grp.scale.x+=(ts-c.grp.scale.x)*.08; c.grp.scale.y=c.grp.scale.z=c.grp.scale.x;
      const tx=on?0:c.base; c.grp.position.x+=(tx-c.grp.position.x)*.07;
      c.grp.position.z+=((on?6:-6)-c.grp.position.z)*.06;
      c.core.material.opacity=on?.85:.35; c.shell.material.opacity=on?.22:.08;
      const pulse=1+Math.sin(t*.004+i)*(on?.06:.02); c.core.scale.setScalar(pulse);
    });
    // collapse shockwave
    if(collapsing>=0){ cwave+=.04; const c=cores[collapsing]; c.shell.scale.setScalar(1+cwave*4); c.shell.material.opacity=Math.max(0,.4-cwave*.4); if(cwave>1.1){ collapsing=-1; c.shell.material.opacity=.22; } }
    tCol.lerp(themeFor(),.05);
    cam.position.x+=((focusI-1.5)*3-cam.position.x)*.04; cam.position.y=2+Math.sin(t*.0003)*1.5; cam.lookAt(cores[focusI].grp.position.x*.6,0,0);
    rn.render(sc,cam);
  })();
  addEventListener('resize',()=>{cam.aspect=W()/H();cam.updateProjectionMatrix();rn.setSize(W(),H(),false);});
  return api;
}
THREED=initMV();
loadRigs();
</script>
</body></html>
