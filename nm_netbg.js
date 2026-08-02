/* ─────────────────────────────────────────────────────────────────────────────
 * NetMon — futuristic network background. A self-contained particle-network
 * canvas: floating nodes drift, link to nearby neighbours, and react to the
 * mouse (links reach out, nodes gently gather). Zero dependencies.
 *
 *   NMNetBG.init({ color:'#4da3ff', density:1, mouseDist:170 });
 *   NMNetBG.setData([{label:'eth1 940Mb', level:'warn'}, {label:'core-sw DOWN', level:'crit'}]);
 *
 * Data nodes are promoted to glowing "hubs" that show a HUD label + pulse ring,
 * coloured by level (ok|info|warn|crit). Call setData() again to refresh; pass
 * [] to clear. Respects prefers-reduced-motion and pauses when the tab hides.
 * ───────────────────────────────────────────────────────────────────────────── */
(function (global) {
  'use strict';

  var LEVEL = {
    ok:   '#2ecc71',
    info: null,            // null → use base accent
    warn: '#f39c12',
    crit: '#e74c3c'
  };

  var NMNetBG = {
    _cv: null, _ctx: null, _raf: null, _running: false,
    _nodes: [], _hubs: [], _w: 0, _h: 0, _dpr: 1,
    _mouse: { x: -9999, y: -9999, active: false },
    _opt: {
      color: '#4da3ff',     // base accent for nodes + links
      density: 1,           // multiplier on auto node count
      maxNodes: 130,
      linkDist: 140,        // px: neighbour link range
      mouseDist: 175,       // px: mouse link range
      speed: 0.28,          // base drift speed
      dotMin: 1.1, dotMax: 2.6,
      lineAlpha: 0.55,      // peak link opacity
      reduceMotion: false
    },

    init: function (opts) {
      var o = this._opt;
      if (opts) for (var k in opts) if (opts.hasOwnProperty(k)) o[k] = opts[k];
      if (global.matchMedia && global.matchMedia('(prefers-reduced-motion: reduce)').matches) o.reduceMotion = true;

      // canvas (reuse if re-init'd)
      var cv = document.getElementById('nm-netbg');
      if (!cv) {
        cv = document.createElement('canvas');
        cv.id = 'nm-netbg';
        cv.style.cssText = 'position:fixed;inset:0;width:100%;height:100%;z-index:-1;pointer-events:none;display:block;';
        document.body.insertBefore(cv, document.body.firstChild);
      }
      this._cv = cv; this._ctx = cv.getContext('2d');

      var self = this;
      this._onResize = function () { self._resize(); };
      this._onMove = function (e) {
        self._mouse.x = e.clientX; self._mouse.y = e.clientY; self._mouse.active = true;
      };
      this._onLeave = function () { self._mouse.active = false; self._mouse.x = self._mouse.y = -9999; };
      this._onVis = function () { document.hidden ? self.stop() : self.start(); };

      global.addEventListener('resize', this._onResize);
      global.addEventListener('mousemove', this._onMove, { passive: true });
      global.addEventListener('mouseout', this._onLeave);
      document.addEventListener('visibilitychange', this._onVis);

      this._resize();
      this.start();
      return this;
    },

    _resize: function () {
      var dpr = global.devicePixelRatio || 1;
      this._dpr = dpr;
      this._w = global.innerWidth; this._h = global.innerHeight;
      this._cv.width = Math.floor(this._w * dpr);
      this._cv.height = Math.floor(this._h * dpr);
      this._ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      this._seed();
    },

    // Populate nodes scaled to viewport area, preserving any existing positions.
    _seed: function () {
      var o = this._opt;
      var target = Math.min(o.maxNodes, Math.round((this._w * this._h) / 16000 * o.density));
      target = Math.max(24, target);
      var n = this._nodes, sp = o.speed;
      while (n.length < target) {
        n.push({
          x: Math.random() * this._w, y: Math.random() * this._h,
          vx: (Math.random() - 0.5) * sp, vy: (Math.random() - 0.5) * sp,
          r: o.dotMin + Math.random() * (o.dotMax - o.dotMin),
          hub: null, ph: Math.random() * Math.PI * 2
        });
      }
      if (n.length > target) n.length = target;
    },

    // Attach data labels → promote a spread-out subset of nodes to glowing hubs.
    setData: function (items) {
      items = items || [];
      // clear previous hubs
      for (var i = 0; i < this._nodes.length; i++) this._nodes[i].hub = null;
      this._hubs = [];
      if (!this._nodes.length) return this;
      var step = Math.max(1, Math.floor(this._nodes.length / Math.max(1, items.length)));
      for (var j = 0; j < items.length; j++) {
        var node = this._nodes[(j * step) % this._nodes.length];
        node.hub = {
          label: String(items[j].label == null ? '' : items[j].label),
          level: items[j].level || 'info',
          val: items[j].value != null ? items[j].value : null
        };
        node.r = Math.max(node.r, 3.2);
        this._hubs.push(node);
      }
      return this;
    },

    _levelColor: function (level) {
      return (LEVEL[level] || this._opt.color);
    },

    start: function () {
      if (this._running) return;
      this._running = true;
      var self = this, last = 0;
      function loop(t) {
        if (!self._running) return;
        self._raf = global.requestAnimationFrame(loop);
        if (t - last < 16) return;       // ~60fps cap
        last = t;
        self._step(); self._draw();
      }
      this._raf = global.requestAnimationFrame(loop);
    },

    stop: function () {
      this._running = false;
      if (this._raf) global.cancelAnimationFrame(this._raf);
    },

    _step: function () {
      var o = this._opt, n = this._nodes, m = this._mouse, W = this._w, H = this._h;
      var still = o.reduceMotion;
      for (var i = 0; i < n.length; i++) {
        var p = n[i];
        if (!still) { p.x += p.vx; p.y += p.vy; }
        // mouse attraction: nearby nodes drift gently toward the cursor
        if (m.active) {
          var dx = m.x - p.x, dy = m.y - p.y, d2 = dx * dx + dy * dy, md = o.mouseDist;
          if (d2 < md * md && d2 > 1) {
            var f = (1 - Math.sqrt(d2) / md) * 0.035;
            p.vx += dx * f * 0.02; p.vy += dy * f * 0.02;
          }
        }
        // damping + speed clamp so the field stays calm
        p.vx *= 0.992; p.vy *= 0.992;
        var sp = Math.sqrt(p.vx * p.vx + p.vy * p.vy), mx = o.speed * 2.2;
        if (sp > mx) { p.vx = p.vx / sp * mx; p.vy = p.vy / sp * mx; }
        if (sp < o.speed * 0.25 && !still) { p.vx += (Math.random() - 0.5) * 0.04; p.vy += (Math.random() - 0.5) * 0.04; }
        // bounce off edges
        if (p.x < 0) { p.x = 0; p.vx = Math.abs(p.vx); } else if (p.x > W) { p.x = W; p.vx = -Math.abs(p.vx); }
        if (p.y < 0) { p.y = 0; p.vy = Math.abs(p.vy); } else if (p.y > H) { p.y = H; p.vy = -Math.abs(p.vy); }
        p.ph += 0.03;
      }
    },

    _hex2rgb: function (h) {
      h = h.replace('#', '');
      if (h.length === 3) h = h[0]+h[0]+h[1]+h[1]+h[2]+h[2];
      return [parseInt(h.substr(0,2),16), parseInt(h.substr(2,2),16), parseInt(h.substr(4,2),16)];
    },

    _draw: function () {
      var ctx = this._ctx, o = this._opt, n = this._nodes, m = this._mouse;
      var W = this._w, H = this._h, base = this._hex2rgb(o.color);
      ctx.clearRect(0, 0, W, H);

      // ── neighbour links ──────────────────────────────────────────────────
      var ld = o.linkDist, ld2 = ld * ld;
      ctx.lineWidth = 1;
      for (var i = 0; i < n.length; i++) {
        for (var k = i + 1; k < n.length; k++) {
          var a = n[i], b = n[k], dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
          if (d2 > ld2) continue;
          var al = (1 - Math.sqrt(d2) / ld) * o.lineAlpha;
          // hub links glow in the hub's level colour
          var c = base;
          if (a.hub) c = this._hex2rgb(this._levelColor(a.hub.level));
          else if (b.hub) c = this._hex2rgb(this._levelColor(b.hub.level));
          ctx.strokeStyle = 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + al.toFixed(3) + ')';
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }

      // ── mouse links ──────────────────────────────────────────────────────
      if (m.active) {
        var mdd = o.mouseDist, mdd2 = mdd * mdd;
        for (var j = 0; j < n.length; j++) {
          var pp = n[j], mdx = pp.x - m.x, mdy = pp.y - m.y, dm2 = mdx * mdx + mdy * mdy;
          if (dm2 > mdd2) continue;
          var mal = (1 - Math.sqrt(dm2) / mdd) * 0.8;
          ctx.strokeStyle = 'rgba(' + base[0] + ',' + base[1] + ',' + base[2] + ',' + mal.toFixed(3) + ')';
          ctx.lineWidth = 1.1;
          ctx.beginPath(); ctx.moveTo(pp.x, pp.y); ctx.lineTo(m.x, m.y); ctx.stroke();
        }
        // cursor core
        ctx.fillStyle = 'rgba(' + base[0] + ',' + base[1] + ',' + base[2] + ',0.9)';
        ctx.beginPath(); ctx.arc(m.x, m.y, 2.4, 0, Math.PI * 2); ctx.fill();
      }

      // ── nodes ────────────────────────────────────────────────────────────
      for (var q = 0; q < n.length; q++) {
        var p = n[q];
        if (p.hub) { this._drawHub(ctx, p); continue; }
        ctx.fillStyle = 'rgba(' + base[0] + ',' + base[1] + ',' + base[2] + ',0.85)';
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
      }
    },

    _drawHub: function (ctx, p) {
      var col = this._hex2rgb(this._levelColor(p.hub.level));
      var rgb = col[0] + ',' + col[1] + ',' + col[2];
      var pulse = 0.5 + 0.5 * Math.sin(p.ph);
      // glow
      var g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, 22 + pulse * 8);
      g.addColorStop(0, 'rgba(' + rgb + ',0.35)');
      g.addColorStop(1, 'rgba(' + rgb + ',0)');
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(p.x, p.y, 22 + pulse * 8, 0, Math.PI * 2); ctx.fill();
      // pulse ring
      ctx.strokeStyle = 'rgba(' + rgb + ',' + (0.5 - pulse * 0.4).toFixed(3) + ')';
      ctx.lineWidth = 1.3;
      ctx.beginPath(); ctx.arc(p.x, p.y, 6 + pulse * 7, 0, Math.PI * 2); ctx.stroke();
      // core
      ctx.fillStyle = 'rgba(' + rgb + ',1)';
      ctx.beginPath(); ctx.arc(p.x, p.y, 3.4, 0, Math.PI * 2); ctx.fill();
      // HUD label — suppressed while the global loader is up (html.nm-loading raises this canvas
      // above the veil for the particle effect; showing CRITICAL/ERROR tags there flashes alarms
      // for a few seconds before the page lands). The glowing hubs still show; only the text hides.
      var label = p.hub.label;
      if (label && !document.documentElement.classList.contains('nm-loading')) {
        ctx.font = '600 11px Consolas,Menlo,monospace';
        var tw = ctx.measureText(label).width;
        var lx = p.x + 11, ly = p.y - 7;
        ctx.fillStyle = 'rgba(8,12,20,0.72)';
        ctx.fillRect(lx - 5, ly - 11, tw + 10, 17);
        ctx.fillStyle = 'rgba(' + rgb + ',0.25)';
        ctx.fillRect(lx - 5, ly - 11, 2, 17);
        ctx.fillStyle = 'rgba(235,240,248,0.95)';
        ctx.fillText(label, lx, ly + 1);
      }
    }
  };

  global.NMNetBG = NMNetBG;
})(window);
