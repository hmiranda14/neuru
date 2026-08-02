/* NEURU Data Vault — cockpit client. Live retention preview is computed in-browser
   (interpolation over per-category min/max ts) so slider drags are instant. */
(function(){
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const GB=1073741824, MB=1048576;
let DATA=null, CHANGED={}, sky=null;

function fmtB(b){ b=+b||0; if(b>=GB) return (b/GB).toFixed(2)+' GB'; if(b>=MB) return (b/MB).toFixed(1)+' MB'; if(b>=1024) return (b/1024).toFixed(0)+' KB'; return b+' B'; }
function fmtN(n){ n=+n||0; if(n>=1e6) return (n/1e6).toFixed(1)+'M'; if(n>=1e3) return (n/1e3).toFixed(1)+'k'; return ''+n; }
function esc(s){ const d=document.createElement('div'); d.textContent=s==null?'':s; return d.innerHTML; }
function flash(msg,ok){ const f=$('#flash'); f.className='flash '+(ok?'ok':'crit'); f.textContent=msg; setTimeout(()=>{f.style.display='none';f.className='flash';},6000); }
async function api(name,opts){ const r=await fetch('vault.php?api='+name,opts); return r.json(); }
async function post(name,body){ const b=new URLSearchParams(body); return api(name,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()}); }

const PAL={syslog:'#4da3ff',netflow:'#22d3ee',devstats:'#9b6bff',latency:'#2ecc71',health:'#e74c3c',events:'#f39c12',audit:'#e0e0e0',wireguard:'#16c79a',biosphere:'#ff7a45',datacore:'#7c4dff',gpu:'#ffd479',tplink:'#00d4a0',cluster:'#5a9bff',security:'#ff5c8a',snapshots:'#c7b3ff',caches:'#8a93a6'};
const col=k=>PAL[k]||'#8a93a6';

// live freeable estimate (interpolation) — matches the server engine's model
function freeable(c,days){ if(!c.rows||!c.min_ts||!c.max_ts) return {rows:0,bytes:0}; const cut=(Date.now()/1000)-days*86400; const span=Math.max(1,c.max_ts-c.min_ts); let frac=cut<=c.min_ts?0:(cut>=c.max_ts?1:(cut-c.min_ts)/span); const rows=Math.round(c.rows*frac); const bytes=Math.round(rows*(c.bytes/Math.max(1,c.rows))); return {rows,bytes}; }

function init(){
  $$('.tabs button').forEach(b=>b.onclick=()=>{ $$('.tabs button').forEach(x=>x.classList.remove('on')); b.classList.add('on'); $$('.pane').forEach(p=>p.classList.remove('on')); $('#p-'+b.dataset.t).classList.add('on'); if(b.dataset.t==='skyline'&&sky) sky.resize(); if(b.dataset.t==='backups') loadBackups(); });
  document.addEventListener('fullscreenchange',()=>{
    // on EXIT, return the particle canvas to the body; keep it inside the fullscreen element otherwise
    if(!document.fullscreenElement){ const bg=document.getElementById('nm-netbg'); if(bg && bg.parentNode!==document.body) document.body.appendChild(bg); }
    if(sky) setTimeout(()=>sky.resize(),80);
  });
  loadStats();
  window.NMVault={init,skyFull};
}
function skyFull(){ const el=document.getElementById('skyline'); if(!el) return;
  if(document.fullscreenElement){ document.exitFullscreen(); return; }
  Promise.resolve((el.requestFullscreen||el.webkitRequestFullscreen||function(){}).call(el))
    .then(()=>{ const bg=document.getElementById('nm-netbg'); if(bg) el.appendChild(bg); })  // particles render behind the towers (z-index:-1)
    .catch(()=>{}); }

async function loadStats(){
  const d=await api('stats'); if(!d.ok){ flash('Could not load vault stats',false); return; } DATA=d; CHANGED={};
  // KPIs
  $('#k-size').innerHTML=fmtB(d.total_bytes);
  const g=d.forecast.growth_per_day||0; $('#k-growth').innerHTML=fmtB(g)+' <small>/day</small>';
  $('#k-free').innerHTML=fmtB(d.freeable_bytes)+' <small>'+fmtN(d.freeable_rows)+' rows</small>';
  const fc=d.forecast;
  if(fc.budget_bytes>0){ $('#k-fc-l').textContent='Budget'; const pct=Math.round(fc.current_bytes/fc.budget_bytes*100); const el=$('#k-fc'); el.innerHTML=pct+'% <small>of '+fmtB(fc.budget_bytes)+'</small>'; el.className='v '+(pct>=100?'crit':pct>=80?'warn':'ok'); }
  else { $('#k-fc-l').textContent='Projected +30d'; $('#k-fc').innerHTML=fmtB(fc.projected_30d); }
  buildSkyline(); buildCats(); fillSelects(); fillForms();
  if(window.NMLoader) NMLoader.hide();   // release the loader only once data + skyline are drawn
}

/* ---- Skyline (WebGL towers) ---- */
function buildSkyline(){
  const host=$('#skyline'); const cats=Object.entries(DATA.categories).filter(([k,c])=>c.bytes>0).sort((a,b)=>b[1].bytes-a[1].bytes);
  $('#legend').innerHTML=cats.map(([k,c])=>`<span><i style="background:${col(k)}"></i>${esc(c.label)} · ${fmtB(c.bytes)}</span>`).join('');
  if(!window.THREE){ host.innerHTML='<div class="note" style="padding:20px">3D view unavailable.</div>'; return; }
  if(sky){ sky.dispose(); host.innerHTML=''; }
  const W=host.clientWidth,H=host.clientHeight||340;
  const scene=new THREE.Scene(); const cam=new THREE.PerspectiveCamera(46,W/H,0.1,1000); cam.position.set(0,26,46);
  const rnd=new THREE.WebGLRenderer({antialias:true,alpha:true}); rnd.setSize(W,H); rnd.setPixelRatio(Math.min(2,devicePixelRatio)); host.appendChild(rnd.domElement);
  scene.add(new THREE.AmbientLight(0x8899bb,0.9)); const dl=new THREE.DirectionalLight(0xffffff,0.9); dl.position.set(20,40,20); scene.add(dl);
  const ctrl=new THREE.OrbitControls(cam,rnd.domElement); ctrl.enableDamping=true; ctrl.maxPolarAngle=Math.PI*0.49; ctrl.minDistance=20; ctrl.maxDistance=90;
  // grid floor
  const grid=new THREE.GridHelper(80,20,0x22314a,0x162032); grid.position.y=0; scene.add(grid);
  const maxB=Math.max(...cats.map(c=>c[1].bytes),1); const n=cats.length; const cols=Math.ceil(Math.sqrt(n)); const gap=7;
  const towers=[];
  cats.forEach(([k,c],i)=>{
    const h=Math.max(1.2, Math.pow(c.bytes/maxB,0.55)*22);
    const x=((i%cols)-(cols-1)/2)*gap, z=(Math.floor(i/cols)-(Math.ceil(n/cols)-1)/2)*gap;
    const geo=new THREE.BoxGeometry(3.6,h,3.6); const mat=new THREE.MeshStandardMaterial({color:col(k),emissive:col(k),emissiveIntensity:0.28,metalness:0.4,roughness:0.35,transparent:true,opacity:0.9});
    const m=new THREE.Mesh(geo,mat); m.position.set(x,h/2,z); m.userData={k,c,targetH:h}; m.scale.y=0.01; scene.add(m); towers.push(m);
    // label sprite
    const cv=document.createElement('canvas'); cv.width=256; cv.height=64; const g2=cv.getContext('2d'); g2.fillStyle='#e6e9ee'; g2.font='bold 26px Segoe UI,sans-serif'; g2.textAlign='center'; g2.fillText(c.label.slice(0,16),128,30); g2.fillStyle='#9fb0c8'; g2.font='20px Segoe UI'; g2.fillText(fmtB(c.bytes),128,54);
    const tx=new THREE.CanvasTexture(cv); const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tx,transparent:true})); sp.scale.set(9,2.25,1); sp.position.set(x,h+2.4,z); scene.add(sp);
  });
  let t=0,raf;
  function loop(){ raf=requestAnimationFrame(loop); t+=0.016; towers.forEach(m=>{ if(m.scale.y<1){ m.scale.y=Math.min(1,m.scale.y+0.05); } m.material.emissiveIntensity=0.22+0.1*Math.sin(t*1.5+m.position.x); }); ctrl.update(); rnd.render(scene,cam); }
  loop();
  sky={ resize(){ const w=host.clientWidth,h2=host.clientHeight||340; cam.aspect=w/h2; cam.updateProjectionMatrix(); rnd.setSize(w,h2); }, dispose(){ cancelAnimationFrame(raf); rnd.dispose(); } };
}

/* ---- Retention category sliders ---- */
function buildCats(){
  const wrap=$('#cats'); const cats=Object.entries(DATA.categories).sort((a,b)=>b[1].bytes-a[1].bytes);
  wrap.innerHTML=cats.map(([k,c])=>{
    const maxDay=Math.max(365,c.compliance);
    return `<div class="glass cat" data-k="${k}">
      <div class="top">
        <div class="ic" style="background:${col(k)}22;color:${col(k)}"><i class="fa-solid ${esc(c.icon)}"></i></div>
        <div><div class="nm">${esc(c.label)}</div><div class="meta">${fmtB(c.bytes)} · ${fmtN(c.rows)} rows${c.oldest?' · oldest '+esc(c.oldest.slice(0,10)):''}${c.setting_key?' · daemon-linked':''}</div></div>
        <div class="sp"></div>
        <label class="meta" style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="en" ${c.enabled?'checked':''}> enabled</label>
        <div class="keep">keep <b class="kd">${c.keep_days}</b> days</div>
      </div>
      <input class="slider" type="range" min="1" max="${maxDay}" value="${c.keep_days}">
      <div class="free">Lower to <b class="fd">${c.keep_days}</b>d → frees <b class="fb">0 B</b> <span class="fr" style="color:#8a93a6"></span></div>
    </div>`;
  }).join('');
  $$('#cats .cat').forEach(card=>{
    const k=card.dataset.k, c=DATA.categories[k];
    const sl=card.querySelector('.slider'), kd=card.querySelector('.kd'), fd=card.querySelector('.fd'), fb=card.querySelector('.fb'), fr=card.querySelector('.fr'), en=card.querySelector('.en');
    const upd=()=>{ const d=+sl.value; kd.textContent=d; fd.textContent=d; const f=freeable(c,d); fb.textContent=fmtB(f.bytes); fr.textContent=f.rows?('· '+fmtN(f.rows)+' rows'):''; if(d!=c.keep_days||en.checked!=!!c.enabled) CHANGED[k]={days:d,enabled:en.checked?1:0}; else delete CHANGED[k]; previewTotal(); };
    sl.oninput=upd; en.onchange=upd;
  });
  previewTotal();
}
function previewTotal(){ let bytes=0,rows=0,any=false; $$('#cats .cat').forEach(card=>{ const k=card.dataset.k,c=DATA.categories[k]; const d=+card.querySelector('.slider').value; const on=card.querySelector('.en').checked; if(on){ const f=freeable(c,d); bytes+=f.bytes; rows+=f.rows; } if(CHANGED[k])any=true; }); const b=$('#preview-banner'); if(any){ b.style.display='block'; b.innerHTML=`<i class="fa-solid fa-wand-magic-sparkles"></i> With these settings, the next cleanup frees about <b>${fmtB(bytes)}</b> (${fmtN(rows)} rows). New DB size ≈ <b>${fmtB(Math.max(0,DATA.total_bytes-bytes))}</b>.`; } else b.style.display='none'; }

function fillSelects(){
  const opt=['<option value="">All categories</option>'].concat(Object.entries(DATA.categories).map(([k,c])=>`<option value="${k}">${esc(c.label)}</option>`)).join('');
  $('#cl-cat').innerHTML=opt;
  $('#rc-cat').innerHTML=Object.entries(DATA.categories).map(([k,c])=>`<option value="${k}">${esc(c.label)} · ${fmtB(c.bytes)}</option>`).join('');
  $('#bk-cats').innerHTML=Object.entries(DATA.categories).map(([k,c])=>`<label class="meta" style="display:flex;align-items:center;gap:5px;background:rgba(255,255,255,.04);padding:4px 9px;border-radius:7px;cursor:pointer"><input type="checkbox" value="${k}"> ${esc(c.label)}</label>`).join('');
}
function fillForms(){
  const ap=DATA.autopilot; $('#ap-budget').value=ap.budget_gb||0; $('#ap-on').value=ap.on?'1':'0'; $('#ap-reclaim').value=ap.reclaim?'1':'0';
  const s=DATA.schedule; $('#sc-freq').value=s.freq||0; $('#sc-kind').value=s.kind||'full'; $('#sc-target').value=s.target||'local'; $('#sc-keep').value=s.keep||7;
}

/* ---- actions ---- */
async function applyPreset(p){ const r=await post('preset',{preset:p}); if(r.ok){ flash('Preset "'+p+'" applied.',true); loadStats(); } else flash('Failed',false); }
window.applyPreset=applyPreset;
window.applyRetention=async function(){ const ks=Object.keys(CHANGED); if(!ks.length){ flash('No changes.',true); return; } for(const k of ks){ await post('set_retention',{category:k,days:CHANGED[k].days,enabled:CHANGED[k].enabled}); } flash('Retention updated for '+ks.length+' categor'+(ks.length>1?'ies':'y')+'. Cleanup runs on schedule, or click “Apply & clean now”.',true); loadStats(); };
window.pruneNow=async function(cat){ if(!confirm('Apply retention and delete data past it now? (chunked, safe)')) return; flash('Cleaning… this runs in the background if large.',true); const r=await post('prune',{category:cat||''}); if(r.ok) flash('Freed '+fmtN(r.freed_rows)+' rows'+(r.stopped_early?' (more will finish on the next run)':'')+'.',true); else flash('Failed: '+(r.error||'?'),false); loadStats(); };
window.cleanup=async function(dry){ const cat=$('#cl-cat').value,days=+$('#cl-days').value; const r=await post('cleanup',{category:cat,days:days,dry:dry?1:''}); const o=$('#cl-out'); if(!r.ok){ o.textContent='Failed: '+(r.error||'?'); return; } const total=Object.values(r.tables||{}).reduce((a,b)=>a+(+b||0),0); o.innerHTML=dry?('Preview: would delete <b>'+fmtN(total)+'</b> rows.'):('Deleted <b>'+fmtN(r.freed_rows)+'</b> rows.'); if(!dry) loadStats(); };
window.reclaim=async function(){ const cat=$('#rc-cat').value; if(!confirm('Optimize this category’s tables? Briefly locks them.')) return; $('#rc-out').textContent='Optimizing…'; const r=await post('reclaim',{category:cat}); $('#rc-out').innerHTML=r.ok?'✅ Reclaimed. Disk size updated.':'Failed: '+(r.error||'?'); if(r.ok) loadStats(); };
window.molt=async function(){ const c=$('#molt-c').value; if(c!=='MOLT'){ flash('Type MOLT to confirm.',false); return; } if(!confirm('MOLT: wipe ALL telemetry (keep config). A full backup is taken first. Continue?')) return; $('#molt-out').textContent='Backing up + molting…'; const r=await post('molt',{confirm:'MOLT'}); if(r.ok){ $('#molt-out').innerHTML='🦋 Reborn. Truncated '+r.truncated+' tables. Safety backup #'+(r.safety_backup||'?')+' saved.'; $('#molt-c').value=''; loadStats(); } else $('#molt-out').innerHTML='Failed: '+esc(r.error||'?'); };
window.saveAutopilot=async function(){ const r=await post('autopilot_save',{budget_gb:$('#ap-budget').value,on:$('#ap-on').value,reclaim:$('#ap-reclaim').value}); flash(r.ok?'Autopilot saved.':'Failed',r.ok); loadStats(); };
window.runAutopilot=async function(){ $('#ap-out').textContent='Running…'; const r=await post('autopilot_run',{}); if(!r.ok){ $('#ap-out').textContent='Failed: '+(r.error||'?'); return; } $('#ap-out').innerHTML=r.ran?('Done. '+(r.changed?('Adjusted: '+r.actions.join(', ')+' · freed '+fmtN(r.freed_rows)+' rows'):'Already under budget — no changes.')):('Not run: '+(r.reason||'disabled')); loadStats(); };
window.saveSchedule=async function(){ const r=await post('schedule_save',{freq:$('#sc-freq').value,kind:$('#sc-kind').value,target:$('#sc-target').value,keep:$('#sc-keep').value}); flash(r.ok?'Schedule saved.':'Failed',r.ok); };
window.saveTargets=async function(){ const r=await post('targets_save',{vault_s3_bucket:$('#t-s3-bucket').value,vault_s3_region:$('#t-s3-region').value,vault_s3_key:$('#t-s3-key').value,vault_s3_endpoint:$('#t-s3-endpoint').value,vault_s3_secret:$('#t-s3-secret').value,vault_webdav_url:$('#t-dav-url').value,vault_webdav_user:$('#t-dav-user').value,vault_webdav_pass:$('#t-dav-pass').value}); flash(r.ok?'Destinations saved.':'Failed',r.ok); };
window.bkKindChange=function(){ $('#bk-cats-wrap').style.display=$('#bk-kind').value==='data'?'block':'none'; };
window.forgeBackup=async function(){ const kind=$('#bk-kind').value; const cats=$$('#bk-cats input:checked').map(x=>x.value); if(kind==='data'&&!cats.length){ flash('Pick at least one category.',false); return; } flash('Forging backup…',true); const r=await post('backup_create',{kind:kind,categories:cats.join(','),target:$('#bk-target').value,passphrase:$('#bk-pass').value,note:$('#bk-note').value}); if(r.ok){ flash(r.inline?'Backup ready.':'Backup started — it will appear below when done.',true); $('#bk-pass').value=''; setTimeout(loadBackups,1200); } else flash('Failed: '+(r.error||'?'),false); };

async function loadBackups(){ const d=await api('backups'); const el=$('#vault-list'); if(!d.ok||!d.backups.length){ el.innerHTML='<div class="note">No backups yet. Forge one above.</div>'; return; }
  const ic={config:'fa-gear',data:'fa-layer-group',full:'fa-database'};
  el.innerHTML=d.backups.map(b=>{ const done=b.status==='done'; return `<div class="cap ${b.encrypted==1?'enc':''}">
    <div class="cr"><i class="fa-solid ${ic[b.kind]||'fa-box'}"></i></div>
    <div style="flex:1;min-width:0"><div class="nm">${esc(b.filename||('#'+b.id+' '+b.kind))} ${b.encrypted==1?'<i class="fa-solid fa-lock" style="color:#ffd479;font-size:11px"></i>':''}</div>
      <div class="meta">${esc(b.kind)} · ${done?fmtB(b.size_bytes):esc(b.error||b.status)} · ${esc((b.created_at||'').slice(0,16))} · ${esc(b.target)}${b.auto==1?' · auto':''}</div></div>
    <span class="st ${esc(b.status)}">${esc(b.status)}</span>
    ${done&&b.path?`<button class="btn ghost sm" onclick="dlBackup(${b.id})"><i class="fa-solid fa-download"></i></button>`:''}
    ${done?`<button class="btn ghost sm" onclick="restoreBackup(${b.id},'${esc(b.kind)}')"><i class="fa-solid fa-rotate-left"></i></button>`:''}
    <button class="btn ghost sm" onclick="delBackup(${b.id})"><i class="fa-solid fa-trash"></i></button>
  </div>`; }).join('');
}
window.dlBackup=id=>{ location.href='vault.php?api=backup_download&id='+id; };
window.delBackup=async id=>{ if(!confirm('Delete this backup?')) return; await post('backup_delete',{id}); loadBackups(); };
window.restoreBackup=async (id,kind)=>{ let pass=''; if(!confirm('RESTORE backup #'+id+'? This overwrites current '+(kind==='config'?'configuration':'data')+'. A safety backup is taken first.')) return; if(kind==='config') pass=prompt('Passphrase (blank if none):')||''; flash('Restoring…',true); const r=await post('backup_restore',{id,passphrase:pass,restore_secret:1}); if(r.ok){ flash('Restored. Safety backup #'+(r.safety||'?')+' saved. Reload the portal.',true); } else flash('Restore failed: '+(r.error||'?'),false); };

document.addEventListener('DOMContentLoaded',init);
})();
