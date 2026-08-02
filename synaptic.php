<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — SYNAPTIC MAP. The player↔machine symbiosis as a live 3D neural map.
// Extends Player DNA: maps how the gamer's real session history (frames, thermals,
// stability, endurance, exploration) forms "synaptic pathways", scores a central
// Synaptic Sync Index, and issues a shareable "Cyborg Profile" card. WebGL, standard
// dark layout. RBAC 'gaming'. Reuses nm_gaming_dna (no new telemetry).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_gaming.php');
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
    if ($api === 'map') {
        $rid = (int)($_GET['rig'] ?? 0);
        if (!$rid) { echo json_encode(['ok'=>false,'error'=>'Pick a rig first.']); exit; }
        $dna = function_exists('nm_gaming_dna') ? nm_gaming_dna($conn,$rid) : ['ok'=>false];
        $tr = $dna['traits'] ?? [];
        $a  = $dna['agg'] ?? [];
        $hours = $dna['hours'] ?? 0;
        // Helper: a plain-English "data behind it" readout per pathway, grounded in REAL numbers.
        $bestFps = (int)($a['best_fps'] ?? 0);
        $stab    = isset($a['stab']) && $a['stab']!==null ? round(((float)$a['stab'])*100) : null;
        $avgTemp = isset($a['avg_max_temp']) && $a['avg_max_temp']!==null ? (int)$a['avg_max_temp'] : null;
        $games   = (int)($a['games'] ?? 0);
        // 5 synaptic pathways ← real DNA traits. Each object MEANS something: value + what it
        // measures + the data behind it (expert) + plain meaning (novice) + how to level it up.
        $syn = [
            ['key'=>'fps','name'=>'FPS Resilience','sub'=>'reflex adaptation when frames drop','v'=>$tr['Frames']??null,'color'=>'#4da3ff',
             'mean'=>'How well your aim survives frame-rate dips. Higher = your hands stay locked on target even when the game stutters.',
             'data'=>$bestFps>0 ? "Best average {$bestFps} FPS · scored against a 144 FPS ceiling" : 'No frame data logged yet — play a session with the Gaming overlay on.',
             'lever'=>'Raise it', 'lever_txt'=>'Free up frames with the FPS Guarantee optimizer.', 'tool'=>'Game Lab', 'url'=>'game_lab.php'],
            ['key'=>'latency','name'=>'Signal Stability','sub'=>'decision-making under stutter/jitter','v'=>$tr['Stability']??null,'color'=>'#36e3d0',
             'mean'=>'How smooth and predictable your frames are. Higher = no sudden hitches to throw off your timing.',
             'data'=>$stab!==null ? "Your 1% low frames sit at {$stab}% of your average — the closer to 100%, the smoother it feels" : 'Not enough sessions to measure frame consistency yet.',
             'lever'=>'Raise it', 'lever_txt'=>'Check if lag is WiFi, ISP or the game itself.', 'tool'=>'Connection Doctor', 'url'=>'net_doctor.php'],
            ['key'=>'thermal','name'=>'Thermal Composure','sub'=>'holding form as the rig heats up','v'=>$tr['Thermals']??null,'color'=>'#ffcf6b',
             'mean'=>'How well your performance holds once the GPU gets hot. Higher = no thermal throttle stealing your frames mid-match.',
             'data'=>$avgTemp!==null ? "Your GPU averages a {$avgTemp}°C peak per session — under ~70°C is ideal, 83°C+ is where throttling bites" : 'No temperature history captured yet.',
             'lever'=>'Raise it', 'lever_txt'=>'Tune a cooler fan curve so heat never throttles you.', 'tool'=>'Fan Profiler', 'url'=>'fan_profiler.php'],
            ['key'=>'endure','name'=>'Endurance','sub'=>'consistency over long sessions','v'=>$tr['Endurance']??null,'color'=>'#a884ff',
             'mean'=>'How much you and the rig have gone the distance together. Grows purely from time played.',
             'data'=>"{$hours}h logged so far · 40h of playtime maxes this pathway",
             'lever'=>'Grow it', 'lever_txt'=>'This one only climbs with playtime — keep at it.', 'tool'=>'Gaming Deck', 'url'=>'gaming.php'],
            ['key'=>'adapt','name'=>'Adaptability','sub'=>'range across different games','v'=>$tr['Explorer']??null,'color'=>'#7CFFB2',
             'mean'=>'How versatile you are across genres. Higher = you adjust fast to whatever you load up.',
             'data'=>"{$games} different game".($games===1?'':'s')." played · 8 unlocks a maxed pathway",
             'lever'=>'Grow it', 'lever_txt'=>'Try a new genre — variety widens this synapse.', 'tool'=>'Gaming Deck', 'url'=>'gaming.php'],
        ];
        // state label per pathway for both audiences
        foreach ($syn as &$s) {
            $v=$s['v'];
            $s['state'] = $v===null ? 'nodata' : ($v>=70 ? 'strong' : ($v>=45 ? 'steady' : 'weak'));
        } unset($s);
        $have = array_filter(array_map(fn($s)=>$s['v'], $syn), fn($x)=>$x!==null);
        $sync = $have ? (int)round(array_sum($have)/count($have)) : 0;
        // Cyborg Profile ← weakest / dominant pathway
        $profile = ['name'=>'Emerging Cyborg','emoji'=>'🌱','desc'=>'Play a few sessions and your neural signature forms here.'];
        if ($have) {
            $vals=[]; foreach($syn as $s) if($s['v']!==null) $vals[$s['key']]=$s['v'];
            asort($vals); $weak=array_key_first($vals); arsort($vals); $strong=array_key_first($vals);
            if (($vals['thermal']??100) < 45)               $profile=['name'=>'Thermal Sensitive','emoji'=>'🌡️','desc'=>'Your precision decays as the GPU heats — cool the rig (Fan Profiler) and you level up.'];
            elseif (($vals['latency']??100) < 45)           $profile=['name'=>'Low-Latency Dependent','emoji'=>'🎯','desc'=>'Deadly when the ping is low, shaky when it rises — Network Auto-Heal is your ally.'];
            elseif ($sync >= 75)                            $profile=['name'=>'Adaptive Cyborg','emoji'=>'🦾','desc'=>'You hold form even when the rig or network wobbles. Elite synchronization.'];
            elseif (($vals['fps']??0) >= 70)                $profile=['name'=>'Frame Hunter','emoji'=>'⚡','desc'=>'Reflexes tuned to high frame-rates — the Competitive FPS profile is made for you.'];
            else                                            $profile=['name'=>'Balanced Operator','emoji'=>'🧠','desc'=>'No glaring weak synapse — a steady, well-rounded neural profile.'];
        }
        log_user_action($conn,'synaptic_map','rig '.$rid);
        echo json_encode(['ok'=>true,'synapses'=>$syn,'sync'=>$sync,'profile'=>$profile,
            'archetype'=>$dna['archetype']??null,'hours'=>$dna['hours']??0,'sessions'=>(int)($dna['agg']['sessions']??0),
            'level'=>(int)($dna['level']??1),'rank'=>$dna['rank']??'Bronze','unlocked'=>(int)($dna['unlocked']??0),'total'=>(int)($dna['total']??0),
            'games'=>(int)($dna['agg']['games']??0)]);
        exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown endpoint']); exit;
}

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php'); nm_gamers_hub_pill();
?>
<video autoplay muted loop playsinline id="bg-video" style="position:fixed;inset:0;z-index:-3;object-fit:cover;min-width:100%;min-height:100%;opacity:.08"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<script src="/three.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --cy:#39e1ff; --pk:#b06bff; --bd:rgba(120,150,255,.16); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04060d; }
body{ margin:0; background:#04060d !important; color:#e6ecf7; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; overflow-x:hidden; }
#nm-netbg{ z-index:0 !important; opacity:.5; }
<?= function_exists('nm_chrome_css') ? nm_chrome_css() : '' ?>
.sy{ max-width:1240px; margin:0 auto; padding:16px 20px 60px; position:relative; z-index:1; }
.sy-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
.sy-head h1{ margin:0; font-size:25px; font-weight:900; display:flex; align-items:center; gap:12px; }
.sy-head h1 i{ color:var(--pk); }
.rigsel{ margin-left:auto; display:flex; align-items:center; gap:8px; }
.rigsel select{ background:rgba(6,12,24,.7); border:1px solid var(--bd); color:#dfeeff; border-radius:10px; padding:9px 12px; font-size:13px; }
.sy-sub{ color:#9fb0d8; font-size:13px; margin:4px 0 12px; }
.sy-grid{ display:grid; grid-template-columns:1.45fr .85fr; gap:16px; align-items:start; }
@media(max-width:900px){ .sy-grid{ grid-template-columns:1fr; } }
.glass{ background:rgba(10,14,30,.5); backdrop-filter:blur(14px); border:1px solid var(--bd); border-radius:18px; }
#mapWrap{ position:relative; height:540px; overflow:hidden; }
#mapWrap:fullscreen{ height:100vh; width:100vw; border-radius:0; background:#04060d; }
#synCanvas{ width:100%; height:100%; display:block; cursor:grab; }
#syncBadge{ position:absolute; top:16px; left:18px; pointer-events:none; }
#syncBadge .n{ font-size:46px; font-weight:900; line-height:1; color:var(--cy); text-shadow:0 0 20px rgba(57,225,255,.5); }
#syncBadge .l{ font-size:11px; letter-spacing:2px; text-transform:uppercase; color:#8fa4c8; }
#syncBadge .rk{ margin-top:6px; font-size:12px; color:#cfe0ff; font-weight:700; }
.mapbtns{ position:absolute; top:14px; right:14px; display:flex; gap:8px; z-index:9; }
.mapbtn{ background:rgba(10,16,34,.72); border:1px solid var(--bd); color:#dbe9ff; border-radius:10px; padding:8px 11px; font-size:12px; font-weight:700; cursor:pointer; display:inline-flex; align-items:center; gap:7px; transition:.15s; }
.mapbtn:hover{ border-color:var(--cy); color:#fff; }
#mapTip{ position:absolute; pointer-events:none; z-index:8; background:rgba(6,12,26,.92); border:1px solid var(--bd); border-radius:10px; padding:7px 11px; font-size:12px; color:#eaf2ff; transform:translate(-50%,-140%); opacity:0; transition:opacity .12s; white-space:nowrap; box-shadow:0 6px 22px rgba(0,0,0,.5); }
#mapDetail{ position:absolute; right:14px; bottom:54px; width:298px; max-width:calc(100% - 28px); padding:14px 15px; border-radius:14px; background:rgba(8,13,28,.88); border:1px solid var(--bd); box-shadow:0 10px 30px rgba(0,0,0,.55); z-index:7; }
#mapDetail .dh{ display:flex; align-items:center; gap:9px; }
#mapDetail .dot{ width:11px; height:11px; border-radius:50%; background:currentColor; box-shadow:0 0 10px currentColor; }
#mapDetail .dn{ font-size:14.5px; font-weight:800; }
#mapDetail .dv{ margin-left:auto; font-size:20px; font-weight:900; font-variant-numeric:tabular-nums; }
#mapDetail .chip{ display:inline-block; font-size:10.5px; font-weight:800; letter-spacing:.4px; padding:2px 8px; border-radius:999px; margin-top:7px; text-transform:uppercase; }
.chip.strong{ background:rgba(124,255,178,.16); color:#7CFFB2; } .chip.steady{ background:rgba(77,163,255,.16); color:#8fc4ff; } .chip.weak{ background:rgba(255,90,122,.16); color:#ff96a9; } .chip.nodata{ background:rgba(160,170,190,.14); color:#aab4c6; }
#mapDetail .row{ margin-top:10px; } #mapDetail .row .k{ font-size:10px; letter-spacing:.5px; text-transform:uppercase; color:#8fa4c8; display:flex; align-items:center; gap:6px; }
#mapDetail .row .t{ font-size:12px; color:#d7e3f7; line-height:1.5; margin-top:2px; }
#mapDetail a.jump{ display:inline-flex; align-items:center; gap:7px; margin-top:11px; text-decoration:none; font-size:12px; font-weight:800; color:#04121f; background:linear-gradient(90deg,var(--cy),#7fe9ff); padding:8px 12px; border-radius:9px; }
#mapLegend{ position:absolute; left:0; right:0; bottom:0; display:flex; gap:14px; flex-wrap:wrap; justify-content:center; padding:8px 12px; background:linear-gradient(0deg,rgba(4,6,13,.85),transparent); font-size:11px; color:#9fb0d8; pointer-events:none; }
#mapLegend span{ display:inline-flex; align-items:center; gap:6px; } #mapLegend i.d{ width:9px; height:9px; border-radius:50%; }
.hint{ position:absolute; left:18px; bottom:36px; font-size:11px; color:#7f90b4; pointer-events:none; }
.side{ display:flex; flex-direction:column; gap:14px; }
.cyborg{ padding:20px; text-align:center; }
.cyborg .emo{ font-size:52px; line-height:1; }
.cyborg .nm{ font-size:22px; font-weight:900; margin-top:8px; background:linear-gradient(90deg,var(--cy),var(--pk)); -webkit-background-clip:text; background-clip:text; color:transparent; }
.cyborg .ds{ font-size:12.5px; color:#c3d3ee; margin-top:8px; line-height:1.55; }
.cyborg .meta{ font-size:11px; color:#8fa4c8; margin-top:12px; }
.syn{ padding:16px 18px; }
.syn h3{ margin:0 0 4px; font-size:15px; font-weight:800; }
.syn .h3s{ font-size:11px; color:#8fa4c8; margin-bottom:10px; }
.srow{ margin-bottom:9px; padding:8px 9px; border-radius:11px; cursor:pointer; border:1px solid transparent; transition:.15s; }
.srow:hover{ background:rgba(255,255,255,.04); border-color:var(--bd); }
.srow.sel{ background:rgba(57,225,255,.07); border-color:rgba(57,225,255,.35); }
.srow .top{ display:flex; justify-content:space-between; align-items:baseline; }
.srow .nm{ font-size:13.5px; font-weight:700; } .srow .vv{ font-size:14px; font-weight:900; font-variant-numeric:tabular-nums; }
.srow .sb{ font-size:11px; color:#8fa4c8; }
.srow .bar{ height:7px; border-radius:6px; background:rgba(255,255,255,.07); margin-top:5px; overflow:hidden; }
.srow .bar i{ display:block; height:100%; border-radius:6px; transition:width .8s cubic-bezier(.2,.8,.2,1); }
</style>

<div class="sy">
  <div class="sy-head">
    <h1><i class="fa-solid fa-brain"></i> Synaptic Map</h1>
    <div class="rigsel"><span style="color:#9fb0d8;font-size:12px">Rig</span><select id="rigSel"><option>Loading…</option></select></div>
  </div>
  <div class="sy-sub" id="sySub">The living neural link between you and your machine — hover or tap any synapse to see what it means and how to level it up.</div>

  <div class="sy-grid">
    <div class="glass" id="mapWrap">
      <canvas id="synCanvas"></canvas>
      <div id="syncBadge"><div class="n" id="syncN">—</div><div class="l">Synaptic Sync</div><div class="rk" id="syncRk"></div></div>
      <div class="mapbtns"><button class="mapbtn" id="fsBtn" title="Fullscreen"><i class="fa-solid fa-expand"></i> Fullscreen</button></div>
      <div id="mapTip"></div>
      <div id="mapDetail" style="display:none"></div>
      <div class="hint"><i class="fa-solid fa-hand-pointer"></i> click a synapse for details</div>
      <div id="mapLegend">
        <span><i class="d" style="background:#8fbfff"></i> node size = strength</span>
        <span><i class="fa-solid fa-bolt" style="color:#ffcf6b"></i> pulse speed = consistency</span>
        <span><i class="fa-regular fa-circle" style="color:#39e1ff"></i> ring = exact score</span>
        <span><i class="d" style="background:#ff5a7a"></i> red = needs work</span>
      </div>
    </div>
    <div class="side">
      <div class="glass cyborg" id="cyborg">
        <div class="emo" id="cyEmo">🌱</div>
        <div class="nm" id="cyName">Reading your signature…</div>
        <div class="ds" id="cyDesc"></div>
        <div class="meta" id="cyMeta"></div>
      </div>
      <div class="glass syn">
        <h3><i class="fa-solid fa-diagram-project" style="color:var(--cy)"></i> Synaptic pathways</h3>
        <div class="h3s">Click one to inspect it on the map.</div>
        <div id="synRows"></div>
      </div>
    </div>
  </div>
</div>

<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let RIG='', GL=null, SYN=[], SEL=-1;
const stateLabel={strong:'Strong synapse',steady:'Steady',weak:'Needs work',nodata:'No data yet'};

async function loadRigs(){
  try{ const d=await fetch('synaptic.php?api=rigs').then(r=>r.json());
    const sel=document.getElementById('rigSel');
    if(d.ok&&d.rigs.length){ sel.innerHTML=d.rigs.map(r=>`<option value="${r.id}">${esc(r.name)}</option>`).join(''); RIG=sel.value; loadMap(); }
    else sel.innerHTML='<option value="">No rigs</option>';
  }catch(e){}
}
document.getElementById('rigSel').addEventListener('change',e=>{RIG=e.target.value;loadMap();});

async function loadMap(){
  if(!RIG) return;
  let d; try{ d=await fetch(`synaptic.php?api=map&rig=${RIG}&_=${Date.now()}`).then(r=>r.json()); }catch(e){ d={ok:false}; }
  if(!d.ok){ document.getElementById('cyName').textContent=esc(d.error||'Could not read this rig.'); return; }
  SYN=d.synapses||[];
  document.getElementById('syncN').textContent=d.sync||0;
  document.getElementById('syncRk').textContent=(d.rank?`${esc(d.rank)} · Lv ${d.level||1}`:'')+(d.total?` · ${d.unlocked||0}/${d.total} unlocks`:'');
  const p=d.profile||{};
  document.getElementById('cyEmo').textContent=p.emoji||'🧠';
  document.getElementById('cyName').textContent=p.name||'—';
  document.getElementById('cyDesc').textContent=p.desc||'';
  document.getElementById('cyMeta').innerHTML=`${d.sessions||0} sessions · ${Math.round((d.hours||0)*10)/10} h played${d.archetype?` · DNA: ${esc(d.archetype.emoji||'')} ${esc(d.archetype.name||'')}`:''}`;
  renderRows();
  if(GL) GL.set(SYN); else GL=initMap(SYN);
  // default-select the weakest pathway that has data (the one worth fixing); else first
  let pick=-1,lo=1e9; SYN.forEach((s,i)=>{ if(s.v!=null && s.v<lo){lo=s.v;pick=i;} });
  if(pick<0) pick=0;
  selectPathway(pick);
}

function renderRows(){
  document.getElementById('synRows').innerHTML=SYN.map((s,i)=>{
    const v=s.v==null?null:s.v; const w=v==null?0:v;
    return `<div class="srow${i===SEL?' sel':''}" data-i="${i}" onclick="selectPathway(${i})"><div class="top"><span class="nm" style="color:${s.color}">${esc(s.name)}</span><span class="vv" style="color:${s.color}">${v==null?'—':v}</span></div><div class="sb">${esc(s.sub)}</div><div class="bar"><i style="width:${w}%;background:${s.color};box-shadow:0 0 10px ${s.color}"></i></div></div>`;
  }).join('');
}

// Selecting a pathway drives BOTH the in-map analytics overlay (visible in fullscreen)
// and the side list highlight, and focuses the 3D node. Novice + expert copy together.
function selectPathway(i){
  const s=SYN[i]; if(!s) return; SEL=i;
  document.querySelectorAll('.srow').forEach(r=>r.classList.toggle('sel', +r.dataset.i===i));
  const st=s.state||'nodata', v=s.v==null?'—':s.v;
  const good=(st==='strong');
  const dd=document.getElementById('mapDetail'); dd.style.display='block';
  dd.innerHTML=`
    <div class="dh"><span class="dot" style="color:${s.color}"></span><span class="dn">${esc(s.name)}</span><span class="dv" style="color:${s.color}">${v}</span></div>
    <span class="chip ${st}">${esc(stateLabel[st]||st)}</span>
    <div class="row"><div class="k"><i class="fa-solid fa-lightbulb"></i> What it means</div><div class="t">${esc(s.mean||'')}</div></div>
    <div class="row"><div class="k"><i class="fa-solid fa-chart-line"></i> The data behind it</div><div class="t">${esc(s.data||'')}</div></div>
    ${good
      ? `<div class="row"><div class="k"><i class="fa-solid fa-circle-check"></i> Status</div><div class="t">This synapse is firing strong — keep it up.</div></div>`
      : `<div class="row"><div class="k"><i class="fa-solid fa-arrow-trend-up"></i> ${esc(s.lever||'Level up')}</div><div class="t">${esc(s.lever_txt||'')}</div></div><a class="jump" href="${esc(s.url||'#')}"><i class="fa-solid fa-arrow-right"></i> Open ${esc(s.tool||'')}</a>`}
  `;
  if(GL) GL.focus(i);
}

// ── WebGL neural map: central sync-core + labelled, gauged, interactive synapses ──
function initMap(syn){
  const cv=document.getElementById('synCanvas'); if(!window.THREE||!cv) return null;
  let W=cv.clientWidth||780, H=cv.clientHeight||540;
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true,powerPreference:'high-performance'});
  rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(W,H,false);
  const sc=new THREE.Scene(), cam=new THREE.PerspectiveCamera(55,W/H,.1,100); cam.position.set(0,1.4,28);
  // WebGL particle starfield in the SCENE so the constellation persists in fullscreen too
  const starGeo=new THREE.BufferGeometry(), SN=620, spp=new Float32Array(SN*3);
  for(let i=0;i<SN;i++){ const rr=24+Math.random()*34, a=Math.random()*Math.PI*2, b=Math.acos(2*Math.random()-1); spp[i*3]=rr*Math.sin(b)*Math.cos(a); spp[i*3+1]=rr*Math.sin(b)*Math.sin(a); spp[i*3+2]=rr*Math.cos(b); }
  starGeo.setAttribute('position',new THREE.BufferAttribute(spp,3));
  const stars=new THREE.Points(starGeo, new THREE.PointsMaterial({color:0x4da3ff,size:0.13,transparent:true,opacity:.55,sizeAttenuation:true})); sc.add(stars);
  const root=new THREE.Group(); root.rotation.x=-0.13; sc.add(root);
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(2.4,1), new THREE.MeshBasicMaterial({color:0x39e1ff,wireframe:true,transparent:true,opacity:.9})); root.add(core);
  const coreGlow=new THREE.Mesh(new THREE.IcosahedronGeometry(3.1,0), new THREE.MeshBasicMaterial({color:0x39e1ff,wireframe:true,transparent:true,opacity:.16})); root.add(coreGlow);
  const impGeo=new THREE.SphereGeometry(.26,8,8);
  let branches=[], nodeMeshes=[], hov=-1, focusIdx=-1;

  function ringLine(rad,a0,a1,col,op){ const seg=56,pts=[]; for(let k=0;k<=seg;k++){ const a=a0+(a1-a0)*k/seg; pts.push(new THREE.Vector3(Math.cos(a)*rad,Math.sin(a)*rad,0)); } return new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), new THREE.LineBasicMaterial({color:col,transparent:true,opacity:op})); }
  function makeLabel(name,val,hex){
    const c=document.createElement('canvas'); c.width=300; c.height=90; const x=c.getContext('2d');
    x.font='900 42px "Segoe UI",sans-serif'; x.fillStyle=hex; x.textAlign='center'; x.shadowColor=hex; x.shadowBlur=16; x.fillText(val,150,40);
    x.shadowBlur=0; x.font='700 21px "Segoe UI",sans-serif'; x.fillStyle='#dbe7fb'; x.fillText(name,150,74);
    const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter;
    const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthTest:false})); sp.scale.set(6.4,1.9,1); return sp;
  }
  function clearBranches(){
    branches.forEach(b=>{ root.remove(b.grp); b.grp.traverse(o=>{ if(o.geometry&&o.geometry!==impGeo) o.geometry.dispose(); if(o.material){ if(o.material.map)o.material.map.dispose(); o.material.dispose(); } }); });
    branches=[]; nodeMeshes=[];
  }
  function build(syn){
    clearBranches();
    const n=syn.length||5;
    syn.forEach((s,i)=>{
      const ang=(i/n)*Math.PI*2 - Math.PI/2, r=11.6; const hex=s.color||'#4da3ff'; const col=new THREE.Color(hex);
      const strength=(s.v==null?.15:s.v/100); const weak=(s.state==='weak')||(s.v==null);
      const ex=Math.cos(ang)*r, ey=Math.sin(ang)*r; const grp=new THREE.Group();
      // axon (fractures/dims when weak) — deterministic jitter (no per-frame randomness)
      const pts=[],seg=7; for(let k=0;k<=seg;k++){ const f=k/seg; const jit=weak?(Math.sin(i*3.1+k*1.7)*.7)*(1-f):0; pts.push(new THREE.Vector3(ex*f+jit, ey*f, Math.sin(k+i)*.3)); }
      grp.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.28+strength*.55})));
      // faint full track + gauge arc (exact score)
      const track=ringLine(2.0,-Math.PI/2,Math.PI*1.5,col,.12); track.position.set(ex,ey,0); grp.add(track);
      const gauge=ringLine(2.0,-Math.PI/2,-Math.PI/2+Math.max(.02,strength)*Math.PI*2,col,.9); gauge.position.set(ex,ey,0); grp.add(gauge);
      // node — size ∝ strength
      const node=new THREE.Mesh(new THREE.IcosahedronGeometry(.75+strength*1.5,0), new THREE.MeshBasicMaterial({color:col,wireframe:true,transparent:true,opacity:.55+strength*.45}));
      node.position.set(ex,ey,0); node.userData.idx=i; grp.add(node); nodeMeshes.push(node);
      // readable label (name + value) so every object literally says what it is
      const lbl=makeLabel(s.name, s.v==null?'—':String(s.v), hex); lbl.position.set(ex, ey+(1.5+strength*1.5)+1.4, 0); grp.add(lbl);
      // travelling impulse
      const imp=new THREE.Mesh(impGeo, new THREE.MeshBasicMaterial({color:weak?0xff5a7a:col,transparent:true,opacity:.9})); grp.add(imp);
      root.add(grp);
      branches.push({grp,node,gauge,imp,ex,ey,strength,weak,phase:i/n});
    });
  }
  build(syn);

  // raycaster: hover tooltip + click-select + drag-to-rotate (gamer-style mouse orbit)
  const ray=new THREE.Raycaster(), m=new THREE.Vector2(); const tip=document.getElementById('mapTip');
  let drag=false, moved=false, px=0, py=0, yaw=0, pitch=-0.13, autoY=true;
  function hits(ev){ const rect=cv.getBoundingClientRect(); m.x=((ev.clientX-rect.left)/rect.width)*2-1; m.y=-((ev.clientY-rect.top)/rect.height)*2+1; ray.setFromCamera(m,cam); return {h:ray.intersectObjects(nodeMeshes,false),rect}; }
  cv.addEventListener('pointerdown',ev=>{ drag=true; moved=false; autoY=false; px=ev.clientX; py=ev.clientY; cv.setPointerCapture&&cv.setPointerCapture(ev.pointerId); });
  addEventListener('pointerup',()=>{ drag=false; });
  cv.addEventListener('pointermove',ev=>{
    if(drag){ const dx=ev.clientX-px, dy=ev.clientY-py; if(Math.abs(dx)+Math.abs(dy)>3) moved=true; yaw+=dx*0.008; pitch=Math.max(-1.1,Math.min(1.1,pitch+dy*0.006)); px=ev.clientX; py=ev.clientY; tip.style.opacity='0'; cv.style.cursor='grabbing'; return; }
    const {h,rect}=hits(ev);
    if(h.length){ const idx=h[0].object.userData.idx; hov=idx; cv.style.cursor='pointer'; const s=SYN[idx]||{};
      tip.innerHTML=`<b style="color:${s.color}">${esc(s.name)}</b> · ${s.v==null?'—':s.v}`;
      tip.style.left=(ev.clientX-rect.left)+'px'; tip.style.top=(ev.clientY-rect.top)+'px'; tip.style.opacity='1';
    } else { hov=-1; cv.style.cursor='grab'; tip.style.opacity='0'; } });
  cv.addEventListener('pointerleave',()=>{ hov=-1; tip.style.opacity='0'; });
  cv.addEventListener('click',ev=>{ if(moved) return; const {h}=hits(ev); if(h.length) selectPathway(h[0].object.userData.idx); });
  cv.addEventListener('wheel',ev=>{ ev.preventDefault(); cam.position.z=Math.max(16,Math.min(42,cam.position.z+ev.deltaY*0.02)); },{passive:false});

  let paused=false, raf=0;
  function resize(){ W=cv.clientWidth; H=cv.clientHeight; if(W&&H){ cam.aspect=W/H; cam.updateProjectionMatrix(); rn.setSize(W,H,false); } }
  addEventListener('resize',resize); document.addEventListener('fullscreenchange',()=>setTimeout(resize,60));
  document.addEventListener('visibilitychange',()=>{ paused=document.hidden; if(!paused){ cancelAnimationFrame(raf); loop(); } });

  function loop(){ if(paused) return; raf=requestAnimationFrame(loop); const t=Date.now();
    stars.rotation.y+=.0004; stars.rotation.x+=.0001;
    core.rotation.y+=.01; core.rotation.x+=.005; coreGlow.rotation.y-=.006; core.scale.setScalar(1+Math.sin(t*.004)*.05);
    if(autoY && hov<0 && !drag) yaw+=0.0010;
    root.rotation.y=yaw; root.rotation.x=pitch;
    branches.forEach((b,i)=>{ b.node.rotation.y+=.02; b.node.rotation.x+=.01;
      const spd=b.weak?.006:(.010+b.strength*.014); b.phase=(b.phase+spd)%1; const f=b.phase;
      b.imp.position.set(b.ex*f, b.ey*f, 0); b.imp.material.opacity=(b.weak?.5:.9)*(1-Math.abs(f-.5)*1.2);
      const hl=(i===focusIdx)?1.3:(i===hov?1.16:1); b.node.scale.setScalar(hl*(1+Math.sin(t*.005+b.ex)*(b.weak?.12:.05)));
      b.node.material.opacity=(i===focusIdx?1:(.55+b.strength*.45)); if(b.gauge) b.gauge.material.opacity=(i===focusIdx?1:.9);
    });
    rn.render(sc,cam);
  }
  loop();
  return { set(s){ build(s); focusIdx=-1; }, focus(i){ focusIdx=i; } };
}
loadRigs();

// Fullscreen toggle — the map + its analytics overlay go full-viewport
document.getElementById('fsBtn').addEventListener('click',()=>{
  const w=document.getElementById('mapWrap');
  if(!document.fullscreenElement){ (w.requestFullscreen||w.webkitRequestFullscreen||function(){}).call(w); }
  else document.exitFullscreen();
});
document.addEventListener('fullscreenchange',()=>{
  const b=document.getElementById('fsBtn'); const on=!!document.fullscreenElement;
  b.innerHTML=on?'<i class="fa-solid fa-compress"></i> Exit':'<i class="fa-solid fa-expand"></i> Fullscreen';
});
</script>
</body></html>
