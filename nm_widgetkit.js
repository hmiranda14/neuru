/* ─────────────────────────────────────────────────────────────────────────────
   NEURU — Widget Kit. The single shared front-end library for the Widget SDK,
   used by BOTH the Command Center (command.php, inline modal) and the dedicated
   Widget Studio (widgets.php, full page). Keeps one source of truth for:
     • renderView()        — declarative view → HTML (stat/list/bar/table)
     • resolve()           — call the data broker (?api=ds), permission-checked server-side
     • mountDeclarative()  — fetch a manifest's needs + render + self-refresh
     • registry API        — list / validate / install / remove
     • mountBuilder()      — the no-code builder UI, mounted into any container
   The SERVER endpoints live on command.php; `base` defaults there.
   ───────────────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';
  const esc = s => (s == null ? '' : String(s)).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const num = v => { v = parseFloat(v); return isNaN(v) ? 0 : v; };
  function tmpl(str, obj) {
    return String(str == null ? '' : str).replace(/\{([a-z0-9_.]+)\}/gi, (_, k) => {
      let v = obj; k.split('.').forEach(p => { v = (v == null ? undefined : v[p]); }); return esc(v == null ? '' : v);
    });
  }
  // Generic rolling history (built across widget refreshes → a live sparkline). Keyed by
  // an arbitrary string so ANY widget/source/field can have a live trend, not just GPU.
  const ROLLHIST = {};
  function rollHist(key, val) { const h = ROLLHIST[key] || (ROLLHIST[key] = []); h.push(num(val)); if (h.length > 48) h.shift(); return h; }
  // Sparkline. fixedMax given → scale 0..fixedMax (e.g. 100 for %); omitted → auto-scale to the
  // series' own min/max so any unit (ms, Mb/s, counts, °C) graphs sensibly.
  function sparkSvg(arr, color, fixedMax) {
    if (!arr || arr.length < 2) return '<svg viewBox="0 0 100 26" preserveAspectRatio="none" style="width:100%;height:26px;"></svg>';
    const W = 100, H = 26, n = arr.length;
    let lo = 0, hi;
    if (fixedMax != null) { hi = fixedMax; }
    else { lo = Math.min.apply(null, arr); hi = Math.max.apply(null, arr); if (hi === lo) { hi = lo + 1; } lo -= (hi - lo) * 0.1; hi += (hi - lo) * 0.1; }
    const span = (hi - lo) || 1;
    const pts = arr.map((v, i) => `${(i / (n - 1) * W).toFixed(1)},${(H - ((Math.max(lo, Math.min(hi, v)) - lo) / span) * (H - 3) - 1.5).toFixed(1)}`).join(' ');
    const area = `0,${H} ${pts} ${W},${H}`;
    return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:26px;"><polygon points="${area}" fill="${color}22"/><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5"/></svg>`;
  }
  function mbFmt(v) { v = num(v); return v >= 1024 ? (v / 1024).toFixed(1) + 'GB' : Math.round(v) + 'MB'; }
  function human(v) { v = num(v); const u = ['', 'K', 'M', 'G', 'T']; let i = 0; while (Math.abs(v) >= 1000 && i < 4) { v /= 1000; i++; } return (i ? v.toFixed(1) : Math.round(v)) + u[i]; }
  // Multiple overlaid lines on a SHARED scale (so in/out are comparable). Nulls dropped per line.
  function linesSvg(arrs, colors, fixedMax) {
    const W = 100, H = 30, valid = arrs.filter(a => a && a.filter(x => x != null).length > 1);
    if (!valid.length) return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:46px;"></svg>`;
    const hi = (fixedMax != null && fixedMax > 0) ? fixedMax : Math.max(1, ...arrs.flat().map(num));
    const poly = (a, c) => { const af = (a || []).filter(x => x != null).map(num); if (af.length < 2) return '';
      const pts = af.map((vv, i) => `${(i / (af.length - 1) * W).toFixed(1)},${(H - (Math.max(0, Math.min(hi, vv)) / hi) * (H - 3) - 1.5).toFixed(1)}`).join(' ');
      return `<polyline points="${pts}" fill="none" stroke="${c}" stroke-width="1.5"/>`; };
    return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:46px;">${arrs.map((a, i) => poly(a, colors[i] || '#4da3ff')).join('')}</svg>`;
  }
  function fmtNum(v) { v = num(v); if (Math.abs(v) >= 1000) return Math.round(v).toLocaleString(); return Number.isInteger(v) ? String(v) : v.toFixed(1); }

  // ── Declarative view → HTML ────────────────────────────────────────────────
  function renderView(v, data) {
    v = v || {}; const src = data[v.from];
    if (v.type === 'stat') {
      let val;
      if (v.agg === 'count') val = Array.isArray(src) ? src.length : 0;
      else if (typeof v.agg === 'string' && v.agg.indexOf('sum:') === 0) { const f = v.agg.slice(4); val = (Array.isArray(src) ? src : []).reduce((s, x) => s + num(x[f]), 0); }
      else if (typeof v.agg === 'string' && v.agg.indexOf('max:') === 0) { const f = v.agg.slice(4), a = (Array.isArray(src) ? src : []).map(x => num(x[f])); val = a.length ? Math.round(Math.max.apply(null, a) * 10) / 10 : 0; }
      else if (typeof v.agg === 'string' && v.agg.indexOf('min:') === 0) { const f = v.agg.slice(4), a = (Array.isArray(src) ? src : []).map(x => num(x[f])); val = a.length ? Math.round(Math.min.apply(null, a) * 10) / 10 : 0; }
      else if (v.value) { const o = Array.isArray(src) ? (src[0] || {}) : (src || {}); val = tmpl(v.value, o); }
      else val = Array.isArray(src) ? src.length : '—';
      const th = v.thresholds || [], nv = num(val);
      const col = th.length >= 2 ? (nv >= th[1] ? '#e74c3c' : nv >= th[0] ? '#f39c12' : '#2ecc71') : '#4da3ff';
      return `<div class="wk-row" style="gap:12px;align-items:center;"><div style="font-size:30px;font-weight:800;color:${col};">${esc(val)}</div><div style="font-size:12px;color:#9aa3ad;">${esc(v.label || '')}</div></div>`;
    }
    if (v.type === 'list') {
      const arr = Array.isArray(src) ? src.slice(0, v.limit || 20) : [];
      return arr.length ? arr.map(x => `<div class="wk-row">${v.dot ? `<span class="wk-dot" style="background:${esc(tmpl(v.dot, x))}"></span>` : ''}
        <div style="flex:1;min-width:0;"><div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><b>${tmpl(v.title || '', x)}</b></div>
        ${v.subtitle ? `<div style="font-size:11px;color:#9aa3ad;">${tmpl(v.subtitle, x)}</div>` : ''}</div>
        ${v.badge ? `<span style="font-size:10px;color:#9aa3ad;">${tmpl(v.badge, x)}</span>` : ''}</div>`).join('') : '<div class="wk-empty">No data</div>';
    }
    if (v.type === 'bar') {
      const arr = Array.isArray(src) ? src.slice(0, v.limit || 10) : [];
      const mx = Math.max(1, ...arr.map(x => num(tmpl(v.value || '0', x))));
      return arr.length ? arr.map(x => { const val = num(tmpl(v.value || '0', x)); return `<div class="wk-row">
        <div style="width:110px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><b>${tmpl(v.label || '', x)}</b></div>
        <div class="wk-bar"><i style="width:${Math.round(val / mx * 100)}%"></i></div>
        <div style="width:52px;text-align:right;font-size:11px;font-family:monospace;">${esc(val)}</div></div>`; }).join('') : '<div class="wk-empty">No data</div>';
    }
    if (v.type === 'table') {
      const arr = Array.isArray(src) ? src.slice(0, v.limit || 20) : []; const cols = v.columns || [];
      return `<table style="width:100%;border-collapse:collapse;font-size:11.5px;"><thead><tr>${cols.map(c => `<th style="text-align:left;color:#8a929c;padding:3px 4px;border-bottom:1px solid rgba(255,255,255,.13);">${esc(c.label || c.field)}</th>`).join('')}</tr></thead>
        <tbody>${arr.map(x => `<tr>${cols.map(c => `<td style="padding:3px 4px;border-bottom:1px solid rgba(255,255,255,.05);">${tmpl('{' + c.field + '}', x)}</td>`).join('')}</tr>`).join('') || `<tr><td class="wk-empty">No data</td></tr>`}</tbody></table>`;
    }
    // GENERIC single-value visuals — work with ANY source + field (not device-specific):
    //   gauge = big value + a bar (vs max), trend = big value + a LIVE sparkline that
    //   accumulates across refreshes. Both available to every user in the no-code builder.
    if (v.type === 'gauge' || v.type === 'trend') {
      const val = statVal(v, data);
      const th = v.thresholds || [];
      const col = th.length >= 2 ? (val >= th[1] ? '#e74c3c' : val >= th[0] ? '#f39c12' : '#2ecc71') : '#4da3ff';
      if (v.type === 'gauge') {
        const max = (v.max != null && v.max > 0) ? v.max : (th.length >= 2 ? Math.max(th[1] * 1.25, val) : 100);
        const pct = max > 0 ? Math.max(0, Math.min(100, val / max * 100)) : 0;
        return `<div class="wk-gauge"><div class="wk-gauge-top"><span style="color:${col}">${esc(fmtNum(val))}</span>${v.unit ? `<em>${esc(v.unit)}</em>` : ''}<small>${esc(v.label || '')}</small></div>
          <div class="wk-gbar"><i style="width:${pct.toFixed(0)}%;background:${col}"></i></div>
          <div class="wk-gbar-sc"><span>0</span><span>${esc(fmtNum(max))}</span></div></div>`;
      }
      const key = 'trend|' + (v.from || 'd') + '|' + (v.agg || v.value || '') + '|' + (v.label || '');
      const hist = rollHist(key, val);
      return `<div class="wk-trend"><div class="wk-trend-top"><span style="color:${col}">${esc(fmtNum(val))}</span>${v.unit ? `<em>${esc(v.unit)}</em>` : ''}<small>${esc(v.label || '')}</small></div>
        <div class="wk-trend-spark">${sparkSvg(hist, col)}</div>
        <div class="wk-trend-foot">live trend · ${hist.length} pts</div></div>`;
    }
    // GENERIC multi-metric line charts — an OBJECT source carrying parallel numeric arrays.
    //   {type:'lines', from, series:[{field,label,unit,color,max}], title?, link?}
    //   Renders one labelled sparkline per series (mixed units → each scales independently).
    if (v.type === 'lines') {
      const o = Array.isArray(src) ? (src[0] || {}) : (src || {});
      const series = v.series || [];
      if (!series.length) return '<div class="wk-empty">No series configured</div>';
      const title = v.title ? (o[v.title] != null ? o[v.title] : v.title) : '';
      const sub = v.subtitle ? (o[v.subtitle] != null ? o[v.subtitle] : v.subtitle) : '';
      const link = v.link ? `<a class="wk-lines-link" href="${esc(v.link)}${o.target_id ? ('?target=' + encodeURIComponent(o.target_id)) : ''}" title="Open in full view"><i class="fas fa-up-right-from-square"></i></a>` : '';
      const hasData = series.some(s => Array.isArray(o[s.field]) && o[s.field].filter(x => x != null).length > 1);
      const rows = series.map(s => {
        const arr = (Array.isArray(o[s.field]) ? o[s.field] : []).filter(x => x != null).map(num);
        const curRaw = (o['cur_' + s.field] != null) ? o['cur_' + s.field] : (arr.length ? arr[arr.length - 1] : null);
        const col = s.color || '#4da3ff';
        return `<div class="wk-lines-row">
          <div class="wk-lines-lab"><span class="wk-lines-dot" style="background:${col}"></span>${esc(s.label || s.field)}<b>${curRaw == null ? '—' : esc(fmtNum(curRaw)) + (s.unit ? esc(s.unit) : '')}</b></div>
          <div class="wk-lines-spark">${sparkSvg(arr, col, s.max != null ? s.max : undefined)}</div>
        </div>`;
      }).join('');
      return `<div class="wk-lines">${(title || link) ? `<div class="wk-lines-h"><b>${esc(title)}</b>${link}</div>` : ''}
        ${sub ? `<div class="wk-lines-sub">${esc(sub)}</div>` : ''}
        ${hasData ? rows : '<div class="wk-empty">Collecting… the charts fill in as samples arrive.</div>'}
        ${o.model ? `<div class="wk-gpu-model"><i class="fas fa-robot"></i> ${esc(o.model)}</div>` : ''}</div>`;
    }
    // GENERIC multi-chart — a LIST where each row carries parallel numeric arrays. Renders
    // ONE titled mini line-chart per row (e.g. top-5 interfaces, each with in/out lines).
    if (v.type === 'charts') {
      const arr0 = Array.isArray(src) ? src : (src && Array.isArray(src.items) ? src.items : []);
      const arr = arr0.slice(0, v.limit || 6);
      if (!arr.length) return '<div class="wk-empty">No data yet — charts fill as samples arrive.</div>';
      const series = v.series || [];
      return arr.map(row => {
        const title = v.title ? tmpl(v.title, row) : '';
        let mx = 0; series.forEach(s => (row[s.field] || []).forEach(x => { const n = num(x); if (n > mx) mx = n; }));
        const svg = linesSvg(series.map(s => row[s.field] || []), series.map(s => s.color || '#4da3ff'), mx || 1);
        const legs = series.map(s => { const a = row[s.field] || [];
          const cur = (row['cur_' + s.field] != null) ? num(row['cur_' + s.field]) : (a.length ? num(a[a.length - 1]) : 0);
          return `<span class="wk-ch-leg"><span class="wk-lines-dot" style="background:${s.color || '#4da3ff'}"></span>${esc(s.label || s.field)} <b>${esc(human(cur))}${v.unit ? esc(v.unit) : ''}</b></span>`; }).join('');
        return `<div class="wk-ch"><div class="wk-ch-h"><b>${esc(title)}</b></div><div class="wk-ch-svg">${svg}</div><div class="wk-ch-legs">${legs}</div></div>`;
      }).join('');
    }
    if (v.type === 'gpu') {
      const arr = Array.isArray(src) ? src : (src ? [src] : []);
      if (!arr.length) return '<div class="wk-empty">No GPU data — add an AI server in the GPU Monitor.</div>';
      return arr.slice(0, v.limit || 4).map(g => {
        const util = num(g.util_pct);
        const vp = (g.vram_pct != null && g.vram_pct !== '') ? num(g.vram_pct) : (num(g.vram_total_mb) ? num(g.vram_used_mb) / num(g.vram_total_mb) * 100 : 0);
        const temp = (g.temp_c != null && g.temp_c !== '') ? num(g.temp_c) : null;
        const pw = (g.power_w != null && g.power_w !== '') ? num(g.power_w) : null;
        const uc = util >= 90 ? '#e74c3c' : util >= 70 ? '#f39c12' : '#76b900';
        const vc = vp >= 90 ? '#e74c3c' : vp >= 75 ? '#f39c12' : '#4da3ff';
        const tc = temp == null ? '#9aa3ad' : (temp >= 85 ? '#e74c3c' : temp >= 70 ? '#f39c12' : '#2ecc71');
        const hist = rollHist((v.from || 'g') + '|' + (g.target || '') + '|' + (g.gpu || ''), util);
        const vram = (g.vram_used_mb != null && g.vram_total_mb != null) ? (mbFmt(g.vram_used_mb) + ' / ' + mbFmt(g.vram_total_mb)) : (vp ? Math.round(vp) + '%' : '—');
        const tid = g.target_id || '';
        return `<div class="wk-gpu">
          <div class="wk-gpu-h"><b title="${esc(g.gpu || 'GPU')}">${esc(g.gpu || 'GPU')}</b><span class="wk-gpu-t">${esc(g.target || '')}</span>
            <a class="wk-gpu-link" href="gpu.php${tid ? ('?target=' + encodeURIComponent(tid)) : ''}" title="Open AI / GPU Monitor"><i class="fas fa-up-right-from-square"></i></a></div>
          <div class="wk-gpu-grid">
            <div class="wk-gpu-big"><div style="color:${uc}">${Math.round(util)}<small>%</small></div><span>GPU util</span></div>
            <div class="wk-gpu-spark">${sparkSvg(hist, uc, 100)}</div>
          </div>
          <div class="wk-gpu-metric"><span>VRAM</span><div class="wk-gpu-bar"><i style="width:${Math.min(100, Math.max(0, vp)).toFixed(0)}%;background:${vc}"></i></div><b>${Math.round(vp)}%</b></div>
          <div class="wk-gpu-sub">${esc(vram)}</div>
          <div class="wk-gpu-chips">
            ${temp != null ? `<span class="wk-gpu-chip" style="border-color:${tc};color:${tc}"><i class="fas fa-temperature-half"></i> ${Math.round(temp)}°C</span>` : ''}
            ${pw != null ? `<span class="wk-gpu-chip"><i class="fas fa-bolt"></i> ${Math.round(pw)}W</span>` : ''}
          </div>
          ${g.model ? `<div class="wk-gpu-model"><i class="fas fa-robot"></i> ${esc(g.model)}</div>` : ''}
        </div>`;
      }).join('');
    }
    return '<div class="wk-empty">Unsupported view</div>';
  }

  // ── Broker + registry API (server lives on `base`, default command.php) ─────
  async function resolve(source, params, base) {
    base = base || 'command.php'; const q = (params && Object.keys(params).length) ? ('&p=' + encodeURIComponent(JSON.stringify(params))) : '';
    try { return await fetch(base + '?api=ds&source=' + encodeURIComponent(source) + q).then(r => r.json()); }
    catch (e) { return { ok: false, error: 'fetch failed' }; }
  }
  async function mountDeclarative(m, el, base) {
    if (!el) return;
    injectCSS();   // renderView emits .wk-* classes — ensure their styles exist on any host page
    const vt = (m.view || {}).type;
    if (vt === 'alarm' || vt === 'sonify') return mountAudio(m, el, base);   // sound widgets
    const draw = async () => {
      const data = {};
      for (const n of (m.needs || [])) { const d = await resolve(n.source, n.params, base); data[n.as || n.source] = (d && d.ok) ? d.data : null; }
      try { el.innerHTML = renderView(m.view || {}, data); } catch (e) { el.innerHTML = '<div class="wk-empty">widget error</div>'; }
    };
    await draw();
    if (el._t) clearInterval(el._t);
    el._t = setInterval(draw, Math.max(5, (m.refresh || 20)) * 1000);
  }

  // ── single number from a view (shared by stat / alarm / sonify) ─────────────
  function statVal(v, data) {
    const src = data[v.from];
    if (v.agg === 'count') return Array.isArray(src) ? src.length : 0;
    if (typeof v.agg === 'string' && v.agg.indexOf('sum:') === 0) { const f = v.agg.slice(4); return (Array.isArray(src) ? src : []).reduce((s, x) => s + num(x[f]), 0); }
    if (typeof v.agg === 'string' && v.agg.indexOf('max:') === 0) { const f = v.agg.slice(4), a = (Array.isArray(src) ? src : []).map(x => num(x[f])); return a.length ? Math.max.apply(null, a) : 0; }
    if (typeof v.agg === 'string' && v.agg.indexOf('min:') === 0) { const f = v.agg.slice(4), a = (Array.isArray(src) ? src : []).map(x => num(x[f])); return a.length ? Math.min.apply(null, a) : 0; }
    if (v.value) { const o = Array.isArray(src) ? (src[0] || {}) : (src || {}); return num(tmpl(v.value, o)); }
    return Array.isArray(src) ? src.length : num(src);
  }
  function cmp(val, thr, op) { return op === '<=' ? val <= thr : op === '<' ? val < thr : op === '>' ? val > thr : op === '==' ? val == thr : val >= thr; }

  // ── per-widget audio engine — lazy AudioContext, MUTED until armed ──────────
  function makeAudio(kind) {
    return {
      AC: null, master: null, osc: null, armed: false, alertT: null,
      ensure() { if (this.AC) return; const AC = this.AC = new (window.AudioContext || window.webkitAudioContext)();
        this.master = AC.createGain(); this.master.gain.value = 0; this.master.connect(AC.destination);
        if (kind === 'sonify') { const o = AC.createOscillator(); o.type = 'sine'; o.frequency.value = 220; o.connect(this.master); o.start(); this.osc = o; } },
      arm(on) { this.armed = on;
        if (on) { this.ensure(); if (this.AC.state === 'suspended') this.AC.resume(); }
        else { if (this.master && this.AC) this.master.gain.setTargetAtTime(0, this.AC.currentTime, 0.2); clearInterval(this.alertT); this.alertT = null; } },
      beep() { if (!this.AC) return; const t = this.AC.currentTime;        // two-tone alarm
        [[880, 0], [660, 0.18]].forEach(p => { const o = this.AC.createOscillator(); o.type = 'square'; o.frequency.value = p[0];
          const g = this.AC.createGain(); g.gain.value = 0; o.connect(g); g.connect(this.AC.destination);
          g.gain.setValueAtTime(0, t + p[1]); g.gain.linearRampToValueAtTime(0.18, t + p[1] + 0.01); g.gain.exponentialRampToValueAtTime(0.0001, t + p[1] + 0.3);
          o.start(t + p[1]); o.stop(t + p[1] + 0.34); }); },
      setAlarm(trip) { if (!this.armed || !this.AC) return;
        if (trip) { if (!this.alertT) { this.beep(); this.alertT = setInterval(() => this.beep(), 1400); } }
        else { clearInterval(this.alertT); this.alertT = null; } },
      setTone(norm) { if (!this.armed || !this.AC || !this.osc) return; const t = this.AC.currentTime; norm = Math.max(0, Math.min(1, norm));
        this.osc.frequency.setTargetAtTime(140 + norm * 740, t, 0.25); this.master.gain.setTargetAtTime(0.05 + norm * 0.12, t, 0.25); }
    };
  }
  async function mountAudio(m, el, base) {
    const v = m.view || {}, kind = v.type;
    const eng = el._audio || (el._audio = makeAudio(kind));
    el.innerHTML =
      '<div class="wk-au ' + kind + '"><div class="wk-au-orb"><i class="fa-solid ' + (kind === 'alarm' ? 'fa-bell' : 'fa-wave-square') + '"></i></div>' +
      '<div class="wk-au-body"><div class="wk-au-state">OFF</div><div class="wk-au-meta">' + esc(v.label || '') + '</div></div>' +
      '<button class="wk-au-btn" title="Arm sound (off by default)"><i class="fa-solid fa-volume-xmark"></i></button></div>';
    const btn = el.querySelector('.wk-au-btn'), card = el.querySelector('.wk-au'),
          st = el.querySelector('.wk-au-state'), meta = el.querySelector('.wk-au-meta');
    btn.onclick = () => { eng.arm(!eng.armed); btn.innerHTML = eng.armed ? '<i class="fa-solid fa-volume-high"></i>' : '<i class="fa-solid fa-volume-xmark"></i>'; btn.classList.toggle('on', eng.armed); draw(); };
    let peak = 1;
    const draw = async () => {
      if (!document.body.contains(el)) { eng.arm(false); if (eng.AC && eng.AC.close) { try { eng.AC.close(); } catch (e) {} } clearInterval(el._t); return; }
      const data = {};
      for (const n of (m.needs || [])) { const d = await resolve(n.source, n.params, base); data[n.as || n.source] = (d && d.ok) ? d.data : null; }
      const val = statVal(v, data);
      if (kind === 'alarm') {
        const thr = num(v.threshold), trip = cmp(val, thr, v.compare || '>=');
        eng.setAlarm(trip);
        card.classList.toggle('trip', trip && eng.armed);
        st.textContent = trip ? 'ALARM' : (eng.armed ? 'ARMED' : 'OFF'); st.style.color = trip ? '#e74c3c' : (eng.armed ? '#2ecc71' : '#8a929c');
        meta.textContent = (v.label ? v.label + ' — ' : '') + val + '  (alarm ' + (v.compare || '>=') + ' ' + thr + ')';
      } else {
        peak = Math.max(peak * 0.97, val, 1); eng.setTone(val / peak);
        st.textContent = (eng.armed ? '♪ ' : '') + val; st.style.color = eng.armed ? '#36e3d0' : '#cfd6df';
        meta.textContent = (v.label ? v.label + ' — ' : '') + 'tone tracks this value';
      }
    };
    await draw();
    if (el._t) clearInterval(el._t);
    el._t = setInterval(draw, Math.max(3, (m.refresh || 10)) * 1000);
  }
  async function apiList(base) { base = base || 'command.php'; try { return await fetch(base + '?api=widgets_list').then(r => r.json()); } catch (e) { return { ok: false }; } }
  async function _post(base, fields) { const fd = new FormData(); Object.keys(fields).forEach(k => fd.append(k, fields[k])); try { return await fetch(base || 'command.php', { method: 'POST', body: fd }).then(r => r.json()); } catch (e) { return { ok: false, errors: ['network error'] }; } }
  function apiValidate(m, base, csrf) { return _post(base, { api: 'widget_validate', csrf, manifest: JSON.stringify(m) }); }
  function apiInstall(m, scope, base, csrf) { return _post(base, { api: 'widget_install', csrf, manifest: JSON.stringify(m), scope: scope || 'user' }); }
  function apiRemove(id, base, csrf) { return _post(base, { api: 'widget_remove', csrf, widget_id: id }); }

  // ── No-code Builder UI, mounted into any container ─────────────────────────
  // opts: { catalog, csrf, base, canGlobal, onSaved(manifest), toast(msg) }
  function mountBuilder(container, opts) {
    opts = opts || {}; const CAT = opts.catalog || {}, base = opts.base || 'command.php', csrf = opts.csrf || '';
    const toast = opts.toast || (m => {});
    injectCSS();
    container.innerHTML = BUILDER_HTML(opts.canGlobal);
    const q = sel => container.querySelector(sel);
    const srcFields = s => (CAT[s] && CAT[s].fields) || [];
    const fieldOpts = (s, sel) => srcFields(s).map(f => `<option ${f === sel ? 'selected' : ''}>${esc(f)}</option>`).join('');
    const curSource = () => q('#wk-source').value;
    const v = id => { const e = q('#' + id); return e ? e.value.trim() : ''; };

    function tab(t) {
      ['build', 'import', 'manage'].forEach(x => { q('#wk-pane-' + x).style.display = x === t ? 'block' : 'none'; });
      container.querySelectorAll('.wk-tab').forEach(b => b.classList.toggle('on', b.dataset.t === t));
      if (t === 'manage') renderManage();
    }
    function populateSources() { const lists = Object.keys(CAT).filter(k => CAT[k].kind === 'list'); q('#wk-source').innerHTML = lists.map(k => `<option value="${esc(k)}">${esc(k)} — ${esc(CAT[k].desc || '')}</option>`).join('') || '<option>(no sources)</option>'; }
    function typeChange() {
      const t = q('#wk-type').value, s = curSource();
      const single = (t === 'stat' || t === 'alarm' || t === 'sonify' || t === 'gauge' || t === 'trend');
      q('#wk-limit-wrap').style.display = single ? 'none' : 'block';
      let h = '';
      if (single) {
        h = `<label>Value <select id="wk-agg" class="wk-in"><option value="count">Count of rows</option><option value="sum">Sum of a field</option><option value="max">Max of a field</option><option value="min">Min of a field</option><option value="value">Value of a field</option></select></label>
          <label id="wk-aggfield-wrap" style="display:none;">Field <select id="wk-aggfield" class="wk-in">${fieldOpts(s)}</select></label>
          <label>Label <input id="wk-label" class="wk-in" placeholder="e.g. nodes down"></label>`;
        if (t === 'gauge' || t === 'trend') h += `<label>Unit (optional) <input id="wk-unit" class="wk-in" placeholder="e.g. % · ms · Mb/s"></label>`;
        if (t === 'gauge') h += `<label>Bar max (optional) <input id="wk-max" class="wk-in" type="number" placeholder="auto (100 / thresholds)"></label>`;
        if (t === 'stat' || t === 'gauge' || t === 'trend') h += `<label>Warn ≥ <input id="wk-twarn" class="wk-in" type="number" placeholder="(optional)"></label>
          <label>Critical ≥ <input id="wk-tcrit" class="wk-in" type="number" placeholder="(optional)"></label>`;
        if (t === 'alarm') h += `<label>Alarm when value <select id="wk-cmp" class="wk-in"><option value="&gt;=">≥ at or above</option><option value="&lt;=">≤ at or below</option></select></label>
          <label>Threshold <input id="wk-thr" class="wk-in" type="number" value="1"></label>`;
      }
      else if (t === 'list') h = `<label>Title <select id="wk-title" class="wk-in">${fieldOpts(s)}</select></label>
        <label>Subtitle <select id="wk-subtitle" class="wk-in"><option value="">— none —</option>${fieldOpts(s)}</select></label>
        <label>Badge <select id="wk-badge" class="wk-in"><option value="">— none —</option>${fieldOpts(s)}</select></label>`;
      else if (t === 'bar') h = `<label>Label <select id="wk-vlabel" class="wk-in">${fieldOpts(s)}</select></label>
        <label>Value (number) <select id="wk-value" class="wk-in">${fieldOpts(s)}</select></label>`;
      else if (t === 'table') for (let i = 0; i < 4; i++) h += `<label>Column ${i + 1} <select id="wk-col${i}" class="wk-in"><option value="">— none —</option>${fieldOpts(s)}</select></label>`;
      q('#wk-map').innerHTML = h + `<div class="wk-fields">Fields: ${srcFields(s).map(esc).join(', ')}</div>`;
      const agg = q('#wk-agg'); if (agg) agg.onchange = () => { q('#wk-aggfield-wrap').style.display = agg.value === 'count' ? 'none' : 'block'; };
      preview();
    }
    function slug(s) { return (s || 'widget').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'widget'; }
    function manifest() {
      const s = curSource(), t = q('#wk-type').value, params = {}, sp = (CAT[s] && CAT[s].params) || {};
      const single = (t === 'stat' || t === 'alarm' || t === 'sonify' || t === 'gauge' || t === 'trend');
      if (sp.limit && !single) params.limit = parseInt(v('wk-limit')) || 10;
      const view = { type: t, from: 'd' }; if (!single) view.limit = parseInt(v('wk-limit')) || 10;
      const setAgg = () => { const a = v('wk-agg'); if (a === 'count') view.agg = 'count'; else if (a === 'sum' || a === 'max' || a === 'min') view.agg = a + ':' + v('wk-aggfield'); else view.value = '{' + v('wk-aggfield') + '}'; };
      const setThresholds = () => { const w = v('wk-twarn'), c = v('wk-tcrit'); if (w !== '' && c !== '') view.thresholds = [parseFloat(w), parseFloat(c)]; };
      if (t === 'stat') { setAgg(); view.label = v('wk-label'); setThresholds(); }
      else if (t === 'gauge') { setAgg(); view.label = v('wk-label'); if (v('wk-unit')) view.unit = v('wk-unit'); if (v('wk-max') !== '') view.max = parseFloat(v('wk-max')); setThresholds(); }
      else if (t === 'trend') { setAgg(); view.label = v('wk-label'); if (v('wk-unit')) view.unit = v('wk-unit'); setThresholds(); }
      else if (t === 'alarm') { setAgg(); view.label = v('wk-label'); view.compare = v('wk-cmp') || '>='; view.threshold = parseFloat(v('wk-thr')) || 0; }
      else if (t === 'sonify') { setAgg(); view.label = v('wk-label'); }
      else if (t === 'list') { view.title = '{' + v('wk-title') + '}'; if (v('wk-subtitle')) view.subtitle = '{' + v('wk-subtitle') + '}'; if (v('wk-badge')) view.badge = '{' + v('wk-badge') + '}'; }
      else if (t === 'bar') { view.label = '{' + v('wk-vlabel') + '}'; view.value = '{' + v('wk-value') + '}'; }
      else if (t === 'table') view.columns = [0, 1, 2, 3].map(i => v('wk-col' + i)).filter(Boolean).map(f => ({ label: f, field: f }));
      const scope = (q('#wk-scope') && q('#wk-scope').value) || 'user';
      return { _scope: scope, sdk: '1.0', id: 'user.' + slug(v('wk-name')), name: v('wk-name') || 'My Widget', icon: v('wk-icon') || 'fa-puzzle-piece', refresh: parseInt(v('wk-refresh')) || 20, needs: [{ source: s, as: 'd', params }], kind: 'declarative', view };
    }
    async function preview() { previewInto(manifest(), q('#wk-preview')); }
    // Generic: render ANY manifest (multi-source) into a box — used by Build + Import previews.
    async function previewInto(m, box) {
      if (!box) return;
      if ((m.kind || 'declarative') !== 'declarative') { box.innerHTML = '<div class="wk-empty">Code widget — no live preview</div>'; return; }
      const vt = (m.view || {}).type;
      if (vt === 'alarm' || vt === 'sonify') { mountDeclarative(m, box, base); return; }   // sound widget — render the card (arm to test)
      box.innerHTML = '<div class="wk-empty">…</div>';
      const data = {};
      for (const n of (m.needs || [])) { const d = await resolve(n.source, n.params, base); data[n.as || n.source] = (d && d.ok) ? d.data : null; }
      try { box.innerHTML = renderView(m.view || {}, data); } catch (e) { box.innerHTML = '<div class="wk-empty">preview error</div>'; }
    }
    function dl(obj) { const o = Object.assign({}, obj); delete o._scope; const b = new Blob([JSON.stringify(o, null, 2)], { type: 'application/json' }); const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = (o.id || 'widget') + '.neuruwidget'; a.click(); URL.revokeObjectURL(a.href); }
    async function save() {
      const m = manifest(); if (!v('wk-name')) { toast('Give it a name'); return; } const scope = m._scope; delete m._scope;
      const r = await apiInstall(m, scope, base, csrf);
      if (!r || !r.ok) { toast((r && r.errors) ? r.errors[0] : 'Save failed'); return; }
      toast('Widget saved'); if (opts.onSaved) opts.onSaved(m); renderManage();
    }
    async function importValidate() { const msg = q('#wk-imsg'); let m; try { m = JSON.parse(v('wk-json')); } catch (e) { msg.innerHTML = '<span style="color:#f0a59d">Not valid JSON</span>'; const pb = q('#wk-ipreview'); if (pb) pb.innerHTML = '<div class="wk-empty">Fix the JSON to preview.</div>'; return null; } const r = await apiValidate(m, base, csrf); if (r && r.ok) { msg.innerHTML = '<span style="color:#9fe0b0">✓ Valid manifest — preview below</span>'; previewInto(m, q('#wk-ipreview')); return m; } msg.innerHTML = '<span style="color:#f0a59d">' + ((r && r.errors) ? r.errors.map(esc).join('<br>') : 'Invalid') + '</span>'; q('#wk-ipreview').innerHTML = '<div class="wk-empty">Fix the errors to preview.</div>'; return null; }
    async function importInstall() { const m = await importValidate(); if (!m) return; const r = await apiInstall(m, 'user', base, csrf); if (!r || !r.ok) { q('#wk-imsg').innerHTML = '<span style="color:#f0a59d">' + ((r && r.errors) ? r.errors[0] : 'Install failed') + '</span>'; return; } toast('Widget installed'); if (opts.onSaved) opts.onSaved(m); renderManage(); }
    async function renderManage() {
      const box = q('#wk-manage'); box.innerHTML = '<div class="wk-empty">…</div>';
      const r = await apiList(base); const mine = (r && r.ok) ? (r.widgets || []).filter(w => w.mine) : [];
      box.innerHTML = mine.length ? mine.map(w => `<div class="wk-mrow"><i class="fa-solid ${esc(w.manifest.icon || 'fa-puzzle-piece')}" style="color:#4da3ff;width:16px;text-align:center;"></i>
        <span style="flex:1;">${esc(w.name)} <span style="color:#7c828c;font-size:10px;">${esc(w.scope)}</span></span>
        <span class="wk-abtn" data-exp="${esc(w.widget_id)}" title="Export"><i class="fa-solid fa-download"></i></span>
        <span class="wk-abtn" data-del="${esc(w.widget_id)}" title="Delete"><i class="fa-solid fa-trash"></i></span></div>`).join('')
        : '<div class="wk-empty">No custom widgets yet. Build or import one.</div>';
      box.querySelectorAll('[data-exp]').forEach(b => b.onclick = () => { const w = mine.find(x => x.widget_id === b.dataset.exp); if (w) dl(w.manifest); });
      box.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { await apiRemove(b.dataset.del, base, csrf); toast('Removed'); if (opts.onSaved) opts.onSaved(null); renderManage(); });
    }

    // wire
    container.querySelectorAll('.wk-tab').forEach(b => b.onclick = () => tab(b.dataset.t));
    q('#wk-source').onchange = typeChange; q('#wk-type').onchange = typeChange;
    q('#wk-prev-btn').onclick = preview; q('#wk-save').onclick = save; q('#wk-export').onclick = () => dl(manifest());
    q('#wk-ival').onclick = importValidate; q('#wk-iinst').onclick = importInstall;
    populateSources(); tab('build'); typeChange();
    return { preview, renderManage };
  }

  function BUILDER_HTML(canGlobal) {
    return `<div class="wk-tabs">
        <button class="wk-tab on" data-t="build">Build</button>
        <button class="wk-tab" data-t="import">Import / AI</button>
        <button class="wk-tab" data-t="manage">My widgets</button></div>
      <div id="wk-pane-build">
        <div class="wk-grid">
          <label>Name <input id="wk-name" class="wk-in" placeholder="e.g. Top Talkers"></label>
          <label>Icon <input id="wk-icon" class="wk-in" value="fa-puzzle-piece"></label>
          <label>Data source <select id="wk-source" class="wk-in"></select></label>
          <label>Visual <select id="wk-type" class="wk-in"><option value="stat">Stat (single number)</option><option value="gauge">Gauge (number + bar)</option><option value="trend">📈 Trend (live graph)</option><option value="list">List</option><option value="bar">Bar chart</option><option value="table">Table</option><option value="alarm">🔔 Alarm (sound)</option><option value="sonify">🎵 Sonify (sound)</option></select></label>
          <label>Refresh (s) <input id="wk-refresh" class="wk-in" type="number" min="5" max="3600" value="20"></label>
          <label id="wk-limit-wrap" style="display:none;">Rows <input id="wk-limit" class="wk-in" type="number" min="1" max="40" value="10"></label>
          ${canGlobal ? `<label>Visibility <select id="wk-scope" class="wk-in"><option value="user">Just me</option><option value="global">Everyone (global)</option></select></label>` : ''}
        </div>
        <div id="wk-map" class="wk-map"></div>
        <div class="wk-prev-h"><span>Live preview</span><button class="wk-abtn" id="wk-prev-btn"><i class="fa-solid fa-rotate"></i> Refresh</button></div>
        <div id="wk-preview" class="wk-prev"><div class="wk-empty">Pick a source to preview.</div></div>
        <div class="wk-act"><span class="wk-abtn ok" id="wk-save"><i class="fa-solid fa-floppy-disk"></i> Save widget</span>
          <span class="wk-abtn" id="wk-export"><i class="fa-solid fa-download"></i> Export JSON</span></div>
      </div>
      <div id="wk-pane-import" style="display:none;">
        <p class="wk-mut">Paste a <b>.neuruwidget</b> JSON (or one an AI wrote for you). See the <a href="widget_sdk.php" style="color:#4da3ff;">SDK guide</a> for the AI prompt.</p>
        <textarea id="wk-json" class="wk-in" style="width:100%;height:180px;font-family:monospace;font-size:12px;" placeholder='{ "sdk":"1.0", "id":"acme.my-widget", ... }'></textarea>
        <div id="wk-imsg" style="font-size:12px;margin:8px 0;"></div>
        <div class="wk-prev-h"><span>Preview</span></div>
        <div id="wk-ipreview" class="wk-prev"><div class="wk-empty">Validate to preview the widget.</div></div>
        <div class="wk-act"><span class="wk-abtn" id="wk-ival"><i class="fa-solid fa-circle-check"></i> Validate &amp; preview</span>
          <span class="wk-abtn ok" id="wk-iinst"><i class="fa-solid fa-download"></i> Install</span></div>
      </div>
      <div id="wk-pane-manage" style="display:none;"><div id="wk-manage"></div></div>`;
  }

  function injectCSS() {
    if (document.getElementById('wk-css')) return;
    const s = document.createElement('style'); s.id = 'wk-css'; s.textContent =
      `.wk-row{display:flex;align-items:center;gap:9px;padding:6px 2px;border-bottom:1px solid rgba(255,255,255,.06);font-size:13px;}
       .wk-dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto;}
       .wk-bar{flex:1;height:6px;background:rgba(255,255,255,.08);border-radius:5px;overflow:hidden;}.wk-bar>i{display:block;height:100%;background:linear-gradient(90deg,#2ecc71,#4da3ff);}
       .wk-empty{color:#5b6470;font-size:12px;text-align:center;padding:14px 0;}
       .wk-gauge-top,.wk-trend-top{display:flex;align-items:baseline;gap:6px;}
       .wk-gauge-top>span,.wk-trend-top>span{font-size:30px;font-weight:800;line-height:1;}
       .wk-gauge-top>em,.wk-trend-top>em{font-style:normal;font-size:13px;color:#8a929c;font-weight:600;}
       .wk-gauge-top>small,.wk-trend-top>small{font-size:11px;color:#9aa3ad;margin-left:auto;}
       .wk-gbar{height:8px;background:rgba(255,255,255,.08);border-radius:6px;overflow:hidden;margin-top:8px;}.wk-gbar>i{display:block;height:100%;border-radius:6px;transition:width .4s;}
       .wk-gbar-sc{display:flex;justify-content:space-between;font-size:9px;color:#6b7480;margin-top:2px;font-family:monospace;}
       .wk-trend-spark{margin-top:6px;opacity:.95;}
       .wk-trend-foot{font-size:9px;color:#6b7480;margin-top:2px;text-transform:uppercase;letter-spacing:.5px;}
       .wk-lines-h{display:flex;align-items:center;gap:7px;font-size:13px;margin-bottom:4px;}.wk-lines-h b{color:#e6e9ee;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
       .wk-lines-link{color:#76b900;flex:0 0 auto;text-decoration:none;font-size:11px;}
       .wk-lines-sub{font-size:10px;color:#8a929c;margin:-2px 0 5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
       .wk-lines-row{margin:6px 0;}
       .wk-lines-lab{display:flex;align-items:center;gap:6px;font-size:11px;color:#9aa3ad;margin-bottom:1px;}
       .wk-lines-lab b{margin-left:auto;font-family:monospace;color:#e6e9ee;font-size:12px;}
       .wk-lines-dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto;}
       .wk-ch{padding:6px 2px 8px;border-bottom:1px solid rgba(255,255,255,.06);}
       .wk-ch-h{font-size:12px;color:#e6e9ee;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:2px;}
       .wk-ch-svg{opacity:.95;}
       .wk-ch-legs{display:flex;gap:12px;flex-wrap:wrap;margin-top:2px;}
       .wk-ch-leg{display:flex;align-items:center;gap:5px;font-size:10.5px;color:#9aa3ad;} .wk-ch-leg b{color:#cfd6df;font-family:monospace;}
       .wk-gpu{padding:7px 2px 9px;border-bottom:1px solid rgba(255,255,255,.06);}
       .wk-gpu-h{display:flex;align-items:center;gap:7px;font-size:13px;margin-bottom:5px;}
       .wk-gpu-h b{color:#e6e9ee;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:60%;}
       .wk-gpu-t{font-size:10px;color:#8a929c;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
       .wk-gpu-link{color:#76b900;flex:0 0 auto;text-decoration:none;font-size:11px;}
       .wk-gpu-grid{display:flex;align-items:center;gap:12px;}
       .wk-gpu-big div{font-size:30px;font-weight:800;line-height:1;}.wk-gpu-big small{font-size:13px;font-weight:600;color:#8a929c;}
       .wk-gpu-big span{font-size:9px;text-transform:uppercase;letter-spacing:.5px;color:#8a929c;}
       .wk-gpu-spark{flex:1;min-width:0;opacity:.92;}
       .wk-gpu-metric{display:flex;align-items:center;gap:7px;margin-top:7px;font-size:11px;color:#9aa3ad;}
       .wk-gpu-metric>span{width:38px;flex:0 0 auto;}.wk-gpu-metric>b{width:34px;text-align:right;font-family:monospace;color:#cfd6df;flex:0 0 auto;}
       .wk-gpu-bar{flex:1;height:6px;background:rgba(255,255,255,.08);border-radius:5px;overflow:hidden;}.wk-gpu-bar>i{display:block;height:100%;border-radius:5px;transition:width .4s;}
       .wk-gpu-sub{font-size:10px;color:#8a929c;font-family:monospace;margin:2px 0 0 45px;}
       .wk-gpu-chips{display:flex;gap:6px;margin-top:7px;flex-wrap:wrap;}
       .wk-gpu-chip{font-size:10px;border:1px solid rgba(255,255,255,.16);color:#aab2bd;border-radius:11px;padding:2px 8px;}
       .wk-gpu-model{margin-top:6px;font-size:10px;color:#aee06a;background:rgba(118,185,0,.1);border:1px solid rgba(118,185,0,.25);border-radius:8px;padding:3px 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
       .wk-au{display:flex;align-items:center;gap:11px;padding:4px 2px;}
       .wk-au-orb{width:38px;height:38px;border-radius:50%;flex:0 0 auto;display:flex;align-items:center;justify-content:center;font-size:16px;color:#4da3ff;background:rgba(77,163,255,.12);border:1px solid rgba(77,163,255,.3);}
       .wk-au.sonify .wk-au-orb{color:#36e3d0;background:rgba(54,227,208,.12);border-color:rgba(54,227,208,.3);}
       .wk-au.trip .wk-au-orb{color:#fff;background:#e74c3c;border-color:#e74c3c;animation:wk-flash .6s steps(1) infinite;}
       .wk-au-body{flex:1;min-width:0;}.wk-au-state{font-weight:800;font-size:14px;letter-spacing:.5px;}.wk-au-meta{font-size:11px;color:#9aa3ad;margin-top:1px;}
       .wk-au-btn{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.16);color:#cfd6df;border-radius:9px;width:38px;height:38px;cursor:pointer;font-size:14px;flex:0 0 auto;}
       .wk-au-btn.on{background:rgba(77,163,255,.22);border-color:#4da3ff;color:#fff;}
       @keyframes wk-flash{0%{opacity:1}50%{opacity:.4}100%{opacity:1}}
       .wk-tabs{display:flex;gap:4px;border-bottom:1px solid rgba(255,255,255,.12);margin-bottom:14px;}
       .wk-tab{background:none;border:none;color:#8a929c;font-size:12.5px;font-weight:700;padding:8px 14px;cursor:pointer;border-bottom:2px solid transparent;}
       .wk-tab.on{color:#fff;border-bottom-color:#4da3ff;}
       .wk-grid,.wk-map{display:grid;grid-template-columns:1fr 1fr;gap:10px 14px;}
       .wk-map{margin-top:12px;padding-top:12px;border-top:1px solid rgba(255,255,255,.12);}
       .wk-grid label,.wk-map label{display:flex;flex-direction:column;gap:4px;font-size:11px;color:#8a929c;font-weight:600;}
       .wk-in{background:#1b2129;color:#e6e9ee;border:1px solid rgba(255,255,255,.13);border-radius:8px;padding:7px 10px;font-size:13px;}
       .wk-fields{grid-column:1/-1;font-size:10.5px;color:#7c828c;}
       .wk-prev-h{display:flex;align-items:center;justify-content:space-between;margin:14px 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#8a929c;}
       .wk-prev{background:rgba(8,12,19,.7);border:1px solid rgba(255,255,255,.13);border-radius:10px;padding:10px 12px;min-height:80px;max-height:240px;overflow:auto;}
       .wk-act{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 4px;}
       .wk-abtn{display:inline-flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;font-weight:600;color:#cfd6df;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.13);padding:6px 12px;border-radius:8px;}
       .wk-abtn:hover{border-color:#4da3ff;color:#fff;}.wk-abtn.ok:hover{border-color:#2ecc71;color:#2ecc71;}
       .wk-mut{color:#8a929c;font-size:12px;}
       .wk-mrow{display:flex;align-items:center;gap:9px;padding:7px 9px;border:1px solid rgba(255,255,255,.13);border-radius:8px;margin-bottom:7px;font-size:12.5px;}`;
    document.head.appendChild(s);
  }

  window.NMWidgetKit = { esc, num, tmpl, renderView, resolve, mountDeclarative, apiList, apiValidate, apiInstall, apiRemove, mountBuilder };
})();
