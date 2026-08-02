/* ─────────────────────────────────────────────────────────────────────────────
   NEURU — NOC-Wall widgets. Reusable, self-hosted (CSP-safe) widget toolkit for
   wall/dashboard pages (geomap.php kiosk + command.php Command Center).

   Today it ships ONE widget — Sonification (ambient audio that maps live network
   state to an A-minor drone, ported from sonify.php) — but it's structured as a
   small registry/dock so more wall widgets can be added later without touching the
   host pages' internals.

   Data model: the host page already polls its telemetry; it just calls
   NMSonify.apply({mbps, err, cpu, down, incidents, threats}) each cycle. No extra
   endpoint, no RBAC coupling — works even for the read-only kiosk user.

   Sound is MUTED BY DEFAULT (AudioContext isn't even created until the first
   un-mute click, satisfying browser autoplay rules).
   ───────────────────────────────────────────────────────────────────────────── */
(function () {
  'use strict';
  function clamp(x, a, b) { return Math.max(a, Math.min(b, x)); }
  function makeCurve(amount) { const n = 256, c = new Float32Array(n), k = amount * 100;
    for (let i = 0; i < n; i++) { const x = i * 2 / n - 1; c[i] = (1 + k) * x / (1 + k * Math.abs(x)); } return c; }

  // ── Audio engine (ported from sonify.php), as a singleton ──────────────────
  const NMSonify = {
    AC: null, master: null, nodes: null, built: false, muted: true, vol: 35,
    alertT: null, mbpsPeak: 20, ui: null, last: null,

    build() {
      if (this.built) return;
      const AC = this.AC = new (window.AudioContext || window.webkitAudioContext)();
      const master = this.master = AC.createGain(); master.gain.value = 0; master.connect(AC.destination);
      const comp = AC.createDynamicsCompressor(); comp.threshold.value = -18; comp.ratio.value = 4; comp.connect(master);
      const lp = AC.createBiquadFilter(); lp.type = 'lowpass'; lp.frequency.value = 900; lp.Q.value = 0.6; lp.connect(comp);
      const shaper = AC.createWaveShaper(); shaper.curve = makeCurve(0); shaper.oversample = '2x';
      const wet = AC.createGain(); wet.gain.value = 0; const dry = AC.createGain(); dry.gain.value = 1;
      shaper.connect(wet); wet.connect(lp); dry.connect(lp);
      const droneGain = AC.createGain(); droneGain.gain.value = 0; droneGain.connect(shaper); droneGain.connect(dry);
      [110.0, 130.81, 164.81].forEach((f, i) => { const o = AC.createOscillator(); o.type = i === 0 ? 'sine' : 'triangle'; o.frequency.value = f;
        const g = AC.createGain(); g.gain.value = 0.22; o.connect(g); g.connect(droneGain); o.start(); });
      const disO = AC.createOscillator(); disO.type = 'sawtooth'; disO.frequency.value = 116.54;
      const disG = AC.createGain(); disG.gain.value = 0; disO.connect(disG); disG.connect(droneGain); disO.start();
      const grO = AC.createOscillator(); grO.type = 'sine'; grO.frequency.value = 55;
      const grG = AC.createGain(); grG.gain.value = 0; grO.connect(grG); grG.connect(dry); grO.start();
      const lfo = AC.createOscillator(); lfo.type = 'sine'; lfo.frequency.value = 0.9;
      const lfoG = AC.createGain(); lfoG.gain.value = 0.08; lfo.connect(lfoG); lfoG.connect(droneGain.gain); lfo.start();
      this.nodes = { lp, shaper, wet, dry, droneGain, disG, grG, lfo, disO };
      droneGain.gain.setTargetAtTime(0.5, AC.currentTime, 1.2);
      this.built = true;
      this._watch();
    },
    // Browsers suspend the AudioContext when the tab is backgrounded/idle; it stays
    // suspended (silent) on return until something resumes it. This watchdog keeps
    // it alive without a page refresh.
    _resume() { try { if (this.AC && this.AC.state === 'suspended') this.AC.resume(); } catch (e) {} },
    _watch() {
      if (this._wd) return; this._wd = 1;
      document.addEventListener('visibilitychange', () => { if (!document.hidden && !this.muted) { this._resume(); if (this.last) this._updateUI(this.last); } });
      setInterval(() => { if (!this.muted) this._resume(); if (this.last) this._updateUI(this.last); }, 4000);
    },

    setMuted(m) {
      this.muted = m;
      if (!m) { this.build(); if (this.AC && this.AC.state === 'suspended') this.AC.resume();
        if (this.master) this.master.gain.setTargetAtTime(this.vol / 100 * 0.5, this.AC.currentTime, 0.3);
        if (this.last) this.apply(this.last); }
      else { if (this.master && this.AC) this.master.gain.setTargetAtTime(0.0001, this.AC.currentTime, 0.3);
        clearInterval(this.alertT); this.alertT = null; }
      this._syncBtn();
    },
    toggle() { this.setMuted(!this.muted); },
    setVol(v) { this.vol = +v; if (this.master && this.AC && !this.muted) this.master.gain.setTargetAtTime(this.vol / 100 * 0.5, this.AC.currentTime, 0.1); },

    apply(d) {
      d = d || {}; this.last = d; this._updateUI(d);
      if (this.muted || !this.built || !this.AC) return;
      this._resume();   // if the browser suspended us while idle, come back to life
      const t = this.AC.currentTime, n = this.nodes;
      this.mbpsPeak = Math.max(this.mbpsPeak * 0.995, d.mbps || 0, 5);
      const load = clamp((d.mbps || 0) / this.mbpsPeak, 0, 1);
      const err = clamp((d.err || 0) / 5, 0, 1);
      const cpu = clamp((d.cpu || 0) / 100, 0, 1);
      const alerts = (d.incidents || 0) + (d.threats || 0);
      n.lfo.frequency.setTargetAtTime(0.7 + load * 3.2, t, 0.5);
      n.lp.frequency.setTargetAtTime(500 + cpu * 4500 + load * 1500, t, 0.6);
      n.disG.gain.setTargetAtTime(err * 0.18, t, 0.8);
      n.shaper.curve = makeCurve(err);
      n.wet.gain.setTargetAtTime(err * 0.6, t, 0.8); n.dry.gain.setTargetAtTime(1 - err * 0.5, t, 0.8);
      n.grG.gain.setTargetAtTime((d.down > 0 ? clamp(d.down * 0.06, 0, 0.25) : 0), t, 0.7);
      clearInterval(this.alertT); this.alertT = null;
      if (alerts > 0) { const every = clamp(8000 / alerts, 1200, 8000); this.alertT = setInterval(() => this.bell(d.down > 0), every); }
    },
    bell(low) { if (!this.AC || this.muted) return; const t = this.AC.currentTime;
      const o = this.AC.createOscillator(); o.type = 'sine'; o.frequency.value = low ? 330 : 880;
      const g = this.AC.createGain(); g.gain.value = 0; o.connect(g); g.connect(this.nodes.dry);
      g.gain.setValueAtTime(0, t); g.gain.linearRampToValueAtTime(0.18, t + 0.01); g.gain.exponentialRampToValueAtTime(0.0001, t + 1.1);
      o.start(t); o.stop(t + 1.2); },

    // Status is driven by the WORST thing happening, in priority order.
    _state(d) { const load = clamp((d.mbps || 0) / this.mbpsPeak, 0, 1);
      if (d.down > 0 || (d.crit || 0) > 0) return ['CRITICAL', '#e74c3c'];
      if ((d.incidents || 0) > 0 || load > 0.8) return ['ELEVATED', '#f39c12'];
      return ['HEALTHY', '#2ecc71']; },
    // Plain-language CAUSE — what is actually driving the status (+ the top offender).
    _reason(d) {
      const load = clamp((d.mbps || 0) / this.mbpsPeak, 0, 1);
      const off = (d.top && d.top.title) ? ' — ' + d.top.title + (d.top.root ? ' (' + d.top.root + ')' : '') : '';
      if (d.down > 0) { const nm = (d.downNames && d.downNames.length) ? ': ' + d.downNames.slice(0, 3).join(', ') + (d.downNames.length > 3 ? '…' : '') : ''; return ['🌑', d.down + ' node' + (d.down > 1 ? 's' : '') + ' DOWN' + nm]; }
      if ((d.crit || 0) > 0) return ['⛔', d.crit + ' critical incident' + (d.crit > 1 ? 's' : '') + off];
      if ((d.incidents || 0) > 0) return ['🔔', d.incidents + ' open incident' + (d.incidents > 1 ? 's' : '') + off];
      if (load > 0.8) return ['🌊', 'heavy traffic load — ' + Math.round(d.mbps || 0) + ' Mb/s'];
      if (load > 0.35) return ['🎵', 'normal traffic — ' + Math.round(d.mbps || 0) + ' Mb/s'];
      return ['🟢', 'all healthy & quiet'];
    },
    _updateUI(d) { if (!this.ui) return; const s = this._state(d), r = this._reason(d);
      if (this.ui.state) { this.ui.state.textContent = s[0]; this.ui.state.style.color = s[1]; }
      if (this.ui.orb) { this.ui.orb.style.setProperty('--nmw-c', s[1]); this.ui.orb.classList.toggle('playing', !this.muted); }
      // why line names the cause; prefix tells you it's the reason for the current status
      if (this.ui.why) this.ui.why.textContent = (this.muted ? '🔇 muted · ' : r[0] + ' ') + 'why ' + s[0] + ': ' + r[1];
      if (this.ui.meta) this.ui.meta.textContent = Math.round(d.mbps || 0) + ' Mb/s · ' + (d.crit || 0) + ' crit · ' + (d.incidents || 0) + ' inc · ' + (d.down || 0) + ' down · cpu ' + Math.round(d.cpu || 0) + '%'; },
    _syncBtn() { if (this.ui && this.ui.btn) { this.ui.btn.innerHTML = this.muted ? '<i class="fa-solid fa-volume-xmark"></i>' : '<i class="fa-solid fa-volume-high"></i>';
      this.ui.btn.classList.toggle('on', !this.muted); } if (this.last) this._updateUI(this.last); }
  };

  // ── Reusable widget chrome ─────────────────────────────────────────────────
  const NMWall = {
    dock: null,
    sonifyHTML() {
      this.injectCSS();
      return '<div class="nmw-row">' +
               '<div class="nmw-orb" title="Overall health — rings pulse while sound is on"><span class="nmw-ring"></span><span class="nmw-ring nmw-r2"></span><span class="nmw-core"></span></div>' +
               '<div class="nmw-body">' +
                 '<div class="nmw-state">MUTED</div>' +
                 '<div class="nmw-why">🔇 sound off — click the speaker to enable ambient audio</div>' +
               '</div>' +
               '<button class="nmw-btn" title="Toggle ambient sound (off by default)"><i class="fa-solid fa-volume-xmark"></i></button>' +
             '</div>' +
             '<div class="nmw-meta">waiting for telemetry…</div>' +
             '<input type="range" min="0" max="100" value="' + NMSonify.vol + '" class="nmw-vol" title="Volume">' +
             '<button class="nmw-info" type="button"><i class="fa-solid fa-circle-question"></i> what am I hearing?</button>' +
             '<div class="nmw-legend">' +
               '<div class="nmw-legintro">Ambient audio turns your network\'s live state into sound, so you can <b>hear</b> trouble without watching the screen. The drone shifts in real time:</div>' +
               '<div class="nmw-leg"><span>🌊</span> pulse speeds up → more <b>traffic load</b></div>' +
               '<div class="nmw-leg"><span>✨</span> tone gets brighter → higher <b>CPU</b></div>' +
               '<div class="nmw-leg"><span>⚡</span> gritty / dissonant → <b>errors</b> rising</div>' +
               '<div class="nmw-leg"><span>🔔</span> bells → <b>open incidents</b> (faster = more)</div>' +
               '<div class="nmw-leg"><span>🌑</span> deep groan → a <b>node is DOWN</b></div>' +
               '<div class="nmw-legc"><b>Status color — driven by the worst thing happening:</b></div>' +
               '<div class="nmw-leg"><span style="color:#2ecc71">●</span> <b>healthy</b> — no open incidents</div>' +
               '<div class="nmw-leg"><span style="color:#f39c12">●</span> <b>elevated</b> — open incident(s) or heavy traffic</div>' +
               '<div class="nmw-leg"><span style="color:#e74c3c">●</span> <b>critical</b> — a node DOWN, or a critical-severity incident</div>' +
               '<div class="nmw-leg" style="margin-top:5px;opacity:.85;">The <b>why</b> line above always names the exact cause + the top incident.</div>' +
             '</div>';
    },
    // Wire NMSonify to a freshly-rendered sonify block (container has the markup).
    wireSonify(root) {
      if (!root) return;
      const btn = root.querySelector('.nmw-btn'), vol = root.querySelector('.nmw-vol'),
            info = root.querySelector('.nmw-info'), legend = root.querySelector('.nmw-legend');
      NMSonify.ui = { orb: root.querySelector('.nmw-orb'), state: root.querySelector('.nmw-state'),
                      why: root.querySelector('.nmw-why'), meta: root.querySelector('.nmw-meta'), btn: btn };
      if (btn && !btn._wired) { btn._wired = 1; btn.addEventListener('click', () => NMSonify.toggle()); }
      if (vol && !vol._wired) { vol._wired = 1; vol.addEventListener('input', e => NMSonify.setVol(e.target.value)); }
      if (info && legend && !info._wired) { info._wired = 1; info.addEventListener('click', () => {
        const open = legend.classList.toggle('open'); info.classList.toggle('open', open); }); }
      NMSonify._syncBtn(); if (NMSonify.last) NMSonify._updateUI(NMSonify.last);
    },
    // Floating dock (used by the geomap kiosk, which has no widget framework of its own).
    ensureDock() {
      if (this.dock) return this.dock;
      this.injectCSS();
      const d = document.createElement('div'); d.id = 'nmw-dock'; document.body.appendChild(d); this.dock = d; return d;
    },
    addSonify() {
      const w = document.createElement('div'); w.className = 'nmw'; w.innerHTML =
        '<div class="nmw-h"><i class="fa-solid fa-satellite-dish"></i> Network Sonar</div>' + this.sonifyHTML();
      this.ensureDock().appendChild(w); this.wireSonify(w); return w;
    },
    injectCSS() {
      if (document.getElementById('nmw-css')) return;
      const s = document.createElement('style'); s.id = 'nmw-css'; s.textContent =
        '#nmw-dock{position:fixed;left:50%;transform:translateX(-50%);bottom:12px;z-index:600;display:flex;gap:10px;flex-wrap:wrap;justify-content:center;}' +
        '.nmw{background:rgba(10,14,22,.92);border:1px solid rgba(255,255,255,.14);border-radius:12px;padding:9px 12px;box-shadow:0 12px 34px rgba(0,0,0,.5);backdrop-filter:blur(12px);color:#e6e9ee;font-family:"Segoe UI",Tahoma,sans-serif;min-width:230px;}' +
        '.nmw-h{font-size:10.5px;text-transform:uppercase;letter-spacing:1.2px;color:#4da3ff;display:flex;align-items:center;gap:6px;margin-bottom:7px;}' +
        '.nmw-row{display:flex;align-items:center;gap:10px;}' +
        '.nmw-orb{--nmw-c:#2ecc71;position:relative;width:34px;height:34px;flex:0 0 auto;display:flex;align-items:center;justify-content:center;margin:3px 4px;}' +
        '.nmw-ring{position:absolute;inset:0;border-radius:50%;border:2px solid var(--nmw-c);opacity:.45;}' +
        '.nmw-ring.nmw-r2{inset:-5px;opacity:.22;}' +
        '.nmw-core{width:13px;height:13px;border-radius:50%;background:var(--nmw-c);box-shadow:0 0 10px var(--nmw-c);transition:background .4s,box-shadow .4s;}' +
        '.nmw-orb.playing .nmw-ring{animation:nmw-pulse 2s ease-out infinite;}.nmw-orb.playing .nmw-ring.nmw-r2{animation-delay:.6s;}' +
        '@keyframes nmw-pulse{0%{transform:scale(.75);opacity:.8;}100%{transform:scale(1.6);opacity:0;}}' +
        '.nmw-body{flex:1;min-width:0;}.nmw-state{font-weight:800;font-size:12.5px;letter-spacing:.4px;color:#2ecc71;}' +
        '.nmw-why{font-size:11px;color:#cdd4dd;margin-top:2px;line-height:1.35;}' +
        '.nmw-meta{font-size:10.5px;color:#8a929c;margin-top:6px;font-family:monospace;}' +
        '.nmw-btn{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.16);color:#cfd6df;border-radius:9px;width:40px;height:40px;cursor:pointer;font-size:15px;flex:0 0 auto;}' +
        '.nmw-btn.on{background:rgba(77,163,255,.22);border-color:#4da3ff;color:#fff;box-shadow:0 0 12px rgba(77,163,255,.4);}' +
        '.nmw-vol{width:100%;height:4px;margin-top:9px;accent-color:#4da3ff;cursor:pointer;}' +
        '.nmw-info{display:block;width:100%;margin-top:8px;background:none;border:none;color:#6f96c8;font-size:10.5px;cursor:pointer;text-align:left;padding:0;}' +
        '.nmw-info:hover{color:#9cc0f0;}.nmw-info.open{color:#9cc0f0;}' +
        '.nmw-legend{display:none;margin-top:7px;padding-top:7px;border-top:1px solid rgba(255,255,255,.10);font-size:10.5px;color:#aab2bc;}' +
        '.nmw-legend.open{display:block;}' +
        '.nmw-legintro{margin-bottom:6px;line-height:1.4;color:#c7cdd6;}' +
        '.nmw-leg{display:flex;gap:8px;align-items:baseline;padding:2px 0;}.nmw-leg span{flex:0 0 16px;text-align:center;}' +
        '.nmw-legc{margin-top:4px;padding-top:5px;border-top:1px solid rgba(255,255,255,.07);}';
      document.head.appendChild(s);
    }
  };

  // Derive a sonify pulse from a typical wall payload (geomap/command share the shape).
  // `down` may be an array of down nodes ([{name,ip}]) or a plain count.
  NMWall.pulseFrom = function (o) {
    o = o || {};
    const nf = o.netflow || [];
    const mbps = nf.reduce((s, t) => s + (t.mbps || 0), 0);
    const inc = o.incidents || [];
    const crit = inc.filter(i => (i.severity === 'critical'));
    const downArr = Array.isArray(o.down) ? o.down : [];
    const downN = Array.isArray(o.down) ? o.down.length : (o.down || 0);
    let cpuSum = 0, cpuN = 0; const nodes = o.nodes || {};
    for (const k in nodes) { const c = nodes[k] && nodes[k].cpu; if (c != null && !isNaN(+c)) { cpuSum += +c; cpuN++; } }
    // top offender — the worst incident, for "why" text
    const top = crit[0] || inc[0] || null;
    return {
      mbps: mbps, cpu: cpuN ? cpuSum / cpuN : 0,
      err: crit.length + downN,            // dissonance driver
      down: downN, downNames: downArr.map(x => x.name || x.ip).filter(Boolean),
      incidents: inc.length, crit: crit.length, threats: 0,
      top: top ? { title: top.title || '', sev: top.severity || '', root: top.root_entity || '' } : null
    };
  };

  window.NMSonify = NMSonify;
  window.NMWall = NMWall;
})();
