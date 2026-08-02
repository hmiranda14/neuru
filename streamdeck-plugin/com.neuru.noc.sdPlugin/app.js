// ─────────────────────────────────────────────────────────────────────────────
// NEURU NOC — Stream Dock / Stream Deck plugin (Elgato-compatible WebSocket model)
//
// Runs on the PC next to VSD Craft. It does NOT compute anything itself — NEURU (on the
// LAN) is the brain: this plugin renders NEURU's button faces (?api=render → setImage),
// polls telemetry to keep them live, and relays key/knob events back (?api=action / ?api=knob).
// Config (NEURU base URL + API token) comes from the Property Inspector (global settings).
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

let ws = null;
let pluginUUID = null;
const NEURU = { base: '', token: '' };

const tiles = {};   // context -> { key }   (Keypad + Knob + SecondaryScreen actions all show a metric)

// Entry point the Stream Dock / Stream Deck software calls.
function connectElgatoStreamDeckSocket(inPort, inPluginUUID, inRegisterEvent, inInfo) {
  pluginUUID = inPluginUUID;
  ws = new WebSocket('ws://127.0.0.1:' + inPort);
  ws.onopen = () => {
    send({ event: inRegisterEvent, uuid: inPluginUUID });
    send({ event: 'getGlobalSettings', context: pluginUUID });
    tryDefaults();   // defaults.json (written by "Deploy to rig") is authoritative — applies even if old global settings persist
    startLoop();
  };
  ws.onmessage = (e) => { try { handle(JSON.parse(e.data)); } catch (_) {} };
}
// Some builds use a lowercase name — expose both.
window.connectStreamDockSocket = connectElgatoStreamDeckSocket;

function send(o) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); }
function plog(msg) { try { if (NEURU.base) fetch(apiUrl('?api=plog&m=' + encodeURIComponent(msg))); } catch (_) {} }
function apiUrl(qs) {
  // base = NEURU origin; tolerate a trailing /stream_decks.php if the user typed the full URL
  const base = (NEURU.base || '').replace(/\/+$/, '').replace(/\/stream_decks\.php$/i, '');
  const sep = qs.indexOf('?') >= 0 ? '&' : '?';
  return base + '/stream_decks.php' + qs + sep + 'token=' + encodeURIComponent(NEURU.token || '');
}

function handle(m) {
  const ev = m.event, ctx = m.context;
  plog('APP ev=' + ev + ' act=' + (m.action || '') + ' ctrl=' + ((m.payload && m.payload.controller) || '') + ' ctx=' + (ctx ? String(ctx).slice(-5) : '') + ' key=' + ((m.payload && m.payload.settings && m.payload.settings.key) || ''));
  switch (ev) {
    case 'didReceiveGlobalSettings': {
      const s = (m.payload && m.payload.settings) || {};
      NEURU.base = s.base || NEURU.base; NEURU.token = s.token || NEURU.token; repaintAll();
      break;
    }
    // Both actions (Keypad tile + Knob + touch bar) show a NEURU metric/action — treat identically.
    // Read key AND tgt from the tile's own settings (VSD Craft persists them per page) — this is what
    // makes multi-page work: switching pages re-fires willAppear with each tile's saved key+tgt.
    case 'willAppear': { const s = (m.payload && m.payload.settings) || {}; const p = m.payload || {}; const co = p.coordinates || {};
      tiles[ctx] = { key: s.key || '', tgt: s.tgt || '', ctrl: p.controller || '', act: m.action || '' };
      // report position + (if configured) key+tgt to NEURU so the in-portal preview MIRRORS the device
      if (NEURU.base) { try {
        let q = '?api=bind&ctx=' + encodeURIComponent(ctx) + '&col=' + (co.column != null ? co.column : (co.col != null ? co.col : 0)) + '&row=' + (co.row != null ? co.row : 0) + '&ctrl=' + encodeURIComponent(p.controller || '');
        if (s.key) q += '&key=' + encodeURIComponent(s.key) + '&tgt=' + encodeURIComponent(s.tgt || '');
        fetch(apiUrl(q));
      } catch (_) {} }
      paint(ctx); break; }
    // page switches ALSO fire willDisappear — must NOT delete the NEURU bind (that erased other pages' tiles),
    // but DO tell NEURU this tile left the visible page (off=1) so the in-portal mirror follows the live page.
    case 'willDisappear':
      if (NEURU.base) { try { fetch(apiUrl('?api=bind&off=1&ctx=' + encodeURIComponent(ctx))); } catch (_) {} }
      delete tiles[ctx]; break;
    case 'didReceiveSettings': { const s = (m.payload && m.payload.settings) || {}; const t = tiles[ctx] || {}; tiles[ctx] = { key: s.key || '', tgt: s.tgt || t.tgt || '', ctrl: (m.payload && m.payload.controller) || t.ctrl || '', act: m.action || t.act || '' }; paint(ctx); break; }
    case 'sendToPlugin': {   // direct PI→plugin: a live-added tile announces its binding → paint now
      const p = m.payload || {};
      if (p.cmd === 'setKey') { tiles[ctx] = { key: p.key || '' }; paint(ctx); }
      break;
    }
    // press a key / push a knob / tap the touch bar → run the bound action on its target rig
    case 'keyDown': case 'dialDown': case 'touchTap': { const t = tiles[ctx] || {}; const k = t.key || (BINDS[ctx] && (BINDS[ctx].k || BINDS[ctx])) || ''; if (k) fireAction(ctx, k, t.tgt || ''); break; }
  }
}

// ── render: pull NEURU's SVG face for this tile → setImage ──
async function paint(ctx) {
  const t = tiles[ctx];
  if (!t || !t.key || !NEURU.base) return;
  try {
    // touch-bar / knob faces render transparent (blend with the pad wallpaper); keys stay opaque.
    const tp = ((t.ctrl && t.ctrl !== 'Keypad') || t.act === 'com.neuru.noc.knob') ? '&t=1' : '';
    const tg = t.tgt ? '&tgt=' + encodeURIComponent(t.tgt) : '';   // per-tile target device
    // NEURU returns a ready base64 PNG data-URI (reliable for setImage); we just hand it over.
    const r = await fetch(apiUrl('?api=render&enc=datauri' + tp + tg + '&key=' + encodeURIComponent(t.key)) + '&_=' + Date.now());
    if (!r.ok) return;
    const dataUri = (await r.text()).trim();
    if (dataUri.slice(0, 10) === 'data:image') send({ event: 'setImage', context: ctx, payload: { image: dataUri, target: 0 } });
  } catch (_) {}
}
let BINDS = {};   // NEURU-side context→key map (bridge around the build's missing setSettings delivery)
async function refreshBinds() { try { const r = await fetch(apiUrl('?api=binds')); if (r.ok) { const j = await r.json(); if (j && j.binds) BINDS = j.binds; } } catch (_) {} }
async function repaintAll() {
  await refreshBinds();
  for (const ctx in tiles) {
    // prefer the tile's own settings (persisted per page); fall back to the NEURU bind (live-add bridge)
    const raw = BINDS[ctx];
    let k = tiles[ctx].key || '', t = tiles[ctx].tgt || '';
    if (raw && typeof raw === 'object') { if (raw.k) k = raw.k; if (raw.t != null && raw.t !== '') t = raw.t; }
    else if (typeof raw === 'string' && raw) { k = raw; }
    if (k) { tiles[ctx].key = k; tiles[ctx].tgt = t; paint(ctx); }
  }
}

// zero-config: NEURU's "Deploy to rig" drops a defaults.json (base+token) into the plugin folder.
async function tryDefaults() {
  try {
    const r = await fetch('defaults.json?_=' + Date.now());
    if (!r.ok) return;
    const d = await r.json();
    if (d && d.base) {
      NEURU.base = d.base; NEURU.token = d.token || '';
      send({ event: 'setGlobalSettings', context: pluginUUID, payload: { base: NEURU.base, token: NEURU.token } });
      repaintAll();
    }
  } catch (_) {}
}

// keep faces live — repaint every 3s (NEURU throttles/caches the underlying SSH itself)
let loopStarted = false;
function startLoop() { if (loopStarted) return; loopStarted = true; setInterval(repaintAll, 3000); }

// ── key press → run the bound NEURU action ──
async function fireAction(ctx, key, tgt) {
  if (!NEURU.base || !key) { send({ event: 'showAlert', context: ctx }); return; }
  try {
    const r = await fetch(apiUrl('?api=action'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: key, tgt: tgt || '' }) });
    const j = await r.json();
    send({ event: j && j.ok ? 'showOk' : 'showAlert', context: ctx });
    if (j && j.nav) send({ event: 'openUrl', payload: { url: (NEURU.base || '').replace(/\/+$/, '') + '/' + j.nav } });
    setTimeout(() => paint(ctx), 500);
  } catch (_) { send({ event: 'showAlert', context: ctx }); }
}
// (rotary control — turning a knob to adjust TDP/audio — is a post-.50 item; needs the build's
//  rotate event captured. For now a NEURU Knob shows a live metric on the knob screen.)
