<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Widget SDK guide (in-portal, beginner-friendly). Explains how to build
// a widget with no code, with AI, or by importing JSON. Renders the LIVE data-source
// catalog so it's always current. RBAC: 'command'. Replaces the raw docs/.md link.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_widgets.php';
require_once __DIR__ . '/nm_chrome.php';
include __DIR__ . '/check.php';
if (!checkAccess($conn, 'command')) { header('Location: /denied_access.php?page=command'); exit; }
require_once __DIR__ . '/logger.php';
log_user_action($conn, 'view_page', 'widget_sdk.php');
nm_widgets_ensure($conn);
$CAT = nm_ds_catalog();
// Build the AI prompt text with the live source list baked in.
$srcLines = [];
foreach ($CAT as $id => $s) $srcLines[] = "  - {$id} ({$s['kind']}): {$s['desc']}. fields: " . implode(', ', $s['fields']);
$AI_PROMPT = "You are writing a NEURU dashboard widget as a single JSON manifest (NEURU Widget SDK 1.0).\n"
  . "Rules: \"sdk\" must be \"1.0\"; \"id\" is namespaced like vendor.name; pick an \"icon\" Font Awesome class; \"kind\":\"declarative\".\n"
  . "Use ONLY these data sources (with the fields shown):\n" . implode("\n", $srcLines) . "\n"
  . "Declarative \"view\" types:\n"
  . "  - stat: { type:\"stat\", from:<alias>, agg:\"count\"|\"sum:FIELD\", label, thresholds:[warn,crit] }\n"
  . "  - list: { type:\"list\", from:<alias>, title:\"{FIELD}\", subtitle:\"{FIELD}\", badge:\"{FIELD}\" }\n"
  . "  - bar:  { type:\"bar\", from:<alias>, label:\"{FIELD}\", value:\"{FIELD}\" }\n"
  . "  - table:{ type:\"table\", from:<alias>, columns:[{label,field}] }\n"
  . "  - alarm: { type:\"alarm\", from:<alias>, agg:\"count\"|\"sum:FIELD\" (or value:\"{FIELD}\"), compare:\">=\"|\"<=\", threshold:N, label } — plays a sound + flashes when the value crosses the threshold (muted until armed)\n"
  . "  - sonify:{ type:\"sonify\", from:<alias>, agg/value (a number), label } — a live tone whose pitch tracks the value (muted until armed)\n"
  . "\"needs\" is an array of { source, as:<alias>, params:{} }. Output ONLY the JSON.\n"
  . "The widget I want: <DESCRIBE IT HERE, e.g. \"top 8 interfaces by total traffic as a bar chart\">";
include __DIR__ . '/header.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Widget SDK Guide | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
<?= nm_chrome_css() ?>
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; overflow-x:hidden; }
a{ color:#4da3ff; }
.doc{ max-width:1000px; margin:0 auto; padding:18px 22px 70px; }
.doc h1{ font-size:24px; font-weight:800; display:flex; align-items:center; gap:12px; margin:0 0 4px; }
.doc h1 i{ color:#4da3ff; } .lead{ color:#9aa3ad; font-size:14px; margin:0 0 22px; }
.card{ background:rgba(255,255,255,0.05); backdrop-filter:blur(20px); border:1px solid rgba(255,255,255,0.12); border-radius:16px; padding:20px 24px; margin-bottom:18px; }
.card h2{ font-size:15px; color:#4da3ff; text-transform:uppercase; letter-spacing:1.2px; margin:0 0 14px; display:flex; align-items:center; gap:9px; }
.card h3{ font-size:14px; margin:16px 0 8px; color:#cfe4ff; }
.card p,.card li{ font-size:13.5px; line-height:1.7; color:#cdd4dd; }
.steps{ list-style:none; padding:0; counter-reset:s; }
.steps li{ position:relative; padding:10px 0 10px 44px; border-bottom:1px solid rgba(255,255,255,.06); }
.steps li:last-child{ border-bottom:none; }
.steps li::before{ counter-increment:s; content:counter(s); position:absolute; left:0; top:9px; width:28px; height:28px; border-radius:50%; background:rgba(77,163,255,.16); color:#7dd3fc; font-weight:800; display:flex; align-items:center; justify-content:center; font-size:13px; }
.ways{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; } @media(max-width:820px){ .ways{ grid-template-columns:1fr; } }
.way{ border:1px solid rgba(255,255,255,.12); border-radius:12px; padding:14px 16px; }
.way .ic{ font-size:22px; color:#4da3ff; margin-bottom:6px; } .way b{ display:block; margin-bottom:4px; }
.way .tag{ font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#2ecc71; font-weight:700; }
.vtypes{ display:grid; grid-template-columns:repeat(2,1fr); gap:12px; } @media(max-width:820px){ .vtypes{ grid-template-columns:1fr; } }
.vt{ border:1px solid rgba(255,255,255,.1); border-radius:10px; padding:12px 14px; } .vt b{ color:#fff; } .vt span{ color:#9aa3ad; font-size:12.5px; }
table.src{ width:100%; border-collapse:collapse; font-size:12.5px; }
table.src th{ text-align:left; color:#8a929c; font-size:10px; text-transform:uppercase; letter-spacing:.5px; padding:7px 8px; border-bottom:1px solid rgba(255,255,255,.13); }
table.src td{ padding:7px 8px; border-bottom:1px solid rgba(255,255,255,.05); vertical-align:top; }
table.src .id{ font-family:monospace; color:#cfe4ff; font-weight:700; white-space:nowrap; }
table.src .perm{ font-size:9.5px; background:rgba(77,163,255,.16); color:#bcd; border-radius:9px; padding:1px 7px; text-transform:uppercase; }
table.src .fl{ font-family:monospace; color:#7c828c; font-size:11px; }
pre{ background:#0a0e15; border:1px solid rgba(255,255,255,.12); border-radius:10px; padding:14px 16px; overflow:auto; font-size:12px; line-height:1.55; color:#cfe4ff; }
.copybtn{ float:right; cursor:pointer; font-size:11px; background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:7px; padding:4px 10px; }
.cta{ display:inline-flex; align-items:center; gap:8px; background:rgba(77,163,255,.16); border:1px solid rgba(77,163,255,.45); color:#cfe4ff; text-decoration:none; padding:10px 18px; border-radius:10px; font-weight:700; font-size:13px; }
.kbd{ font-family:monospace; background:rgba(255,255,255,.08); border-radius:5px; padding:1px 6px; font-size:12px; }
</style>
</head>
<body>
<div class="doc">
  <h1><i class="fa-solid fa-graduation-cap"></i> Widget SDK — make your own widgets</h1>
  <p class="lead">Add custom panels to your <a href="command.php">Command Center</a> — no programming needed. This guide walks you through it.</p>

  <div class="card">
    <h2><i class="fa-solid fa-lightbulb"></i> What is a widget?</h2>
    <p>A widget is a small panel that shows live data from NEURU — a number, a list, a bar chart, or a table. You choose <b>what data</b> it shows (from a ready-made list) and <b>how</b> it looks. NEURU fetches the data for you using <i>your own</i> permissions, so widgets are safe to share — they can't see anything you can't.</p>
    <p style="margin-top:14px;"><a class="cta" href="widgets.php"><i class="fa-solid fa-puzzle-piece"></i> Open Widget Studio to build one</a></p>
  </div>

  <div class="card">
    <h2><i class="fa-solid fa-route"></i> Three ways to make one</h2>
    <div class="ways">
      <div class="way"><div class="ic"><i class="fa-solid fa-wand-magic-sparkles"></i></div><span class="tag">Easiest</span><b>1 · No-code builder</b>
        <p>Fill a short form: pick a data source, pick a look, map a few fields. Watch the live preview, then Save.</p></div>
      <div class="way"><div class="ic"><i class="fa-solid fa-robot"></i></div><span class="tag">Fastest</span><b>2 · Ask an AI</b>
        <p>Describe the widget in plain English to any AI using the prompt below. Paste what it gives you into the <b>Import</b> tab.</p></div>
      <div class="way"><div class="ic"><i class="fa-solid fa-file-code"></i></div><span class="tag">Advanced</span><b>3 · Import JSON</b>
        <p>Already have a widget file (<span class="kbd">.neuruwidget</span>)? Paste it in the Import tab and click Install.</p></div>
    </div>
  </div>

  <div class="card">
    <h2><i class="fa-solid fa-list-ol"></i> Build one in the no-code builder</h2>
    <ol class="steps">
      <li>Open <a href="widgets.php">Widget Studio</a> (or click <b>＋ Create / Import widget</b> in the Command Center's Widgets menu).</li>
      <li>Give it a <b>Name</b> and pick an <b>Icon</b> (any Font Awesome name, e.g. <span class="kbd">fa-fire</span>).</li>
      <li>Choose a <b>Data source</b> — the information it shows (see the full list below).</li>
      <li>Choose a <b>Visual</b> — Stat, List, Bar chart, or Table.</li>
      <li><b>Map the fields</b> with the dropdowns (e.g. for a bar chart: Label = name, Value = a number).</li>
      <li>Check the <b>Live preview</b>, then click <b>Save widget</b>. It appears on your Command Center right away.</li>
    </ol>
  </div>

  <div class="card">
    <h2><i class="fa-solid fa-shapes"></i> The six looks (4 visual + 2 sound)</h2>
    <div class="vtypes">
      <div class="vt"><b>Stat</b> — one big number. <span>e.g. count of open incidents, with green/amber/red thresholds.</span></div>
      <div class="vt"><b>List</b> — rows with a title, subtitle and badge. <span>e.g. nodes and their status.</span></div>
      <div class="vt"><b>Bar chart</b> — labelled bars sized by a value. <span>e.g. top interfaces by traffic.</span></div>
      <div class="vt"><b>Table</b> — pick columns from the source's fields. <span>e.g. interface, in, out.</span></div>
      <div class="vt"><b>🔔 Alarm (sound)</b> — pick a value + threshold; plays a two-tone alarm and flashes when crossed. <span>e.g. beep when any node is down. Muted until you arm it.</span></div>
      <div class="vt"><b>🎵 Sonify (sound)</b> — a live tone whose pitch follows one value. <span>e.g. hear bandwidth rise and fall — a mini Network Sonar. Muted until armed.</span></div>
    </div>
  </div>

  <div class="card">
    <h2><i class="fa-solid fa-database"></i> Available data sources (<?= count($CAT) ?>)</h2>
    <p style="margin-top:0;">These are everything a widget can read. Each needs the permission shown — you'll only see data you're allowed to.</p>
    <table class="src"><thead><tr><th>Source</th><th>Permission</th><th>Shows</th><th>Fields you can map</th></tr></thead><tbody>
    <?php foreach ($CAT as $id => $s): ?>
      <tr><td class="id"><?= htmlspecialchars($id) ?></td><td><span class="perm"><?= htmlspecialchars($s['perm']) ?></span></td>
          <td><?= htmlspecialchars($s['desc']) ?></td><td class="fl"><?= htmlspecialchars(implode(' · ', $s['fields'])) ?></td></tr>
    <?php endforeach; ?>
    </tbody></table>
  </div>

  <div class="card">
    <h2><i class="fa-solid fa-robot"></i> Let an AI build it for you</h2>
    <p>Copy this prompt into ChatGPT/Claude/etc., replace the last line with what you want, and paste the JSON it returns into the <b>Import / AI</b> tab in Widget Studio.</p>
    <pre><button class="copybtn" onclick="copyPrompt()"><i class="fa-solid fa-copy"></i> Copy</button><code id="ai-prompt"><?= htmlspecialchars($AI_PROMPT) ?></code></pre>
  </div>

  <div class="card">
    <h2><i class="fa-solid fa-code"></i> What a widget file looks like (for the curious)</h2>
    <p>A widget is just this small JSON. The builder writes it for you — you rarely need to see it.</p>
<pre><code>{
  "sdk": "1.0",
  "id": "acme.top-talkers",
  "name": "Top Talkers",
  "icon": "fa-fire",
  "refresh": 20,
  "needs": [ { "source": "netflow.top", "as": "nf", "params": { "limit": 8 } } ],
  "kind": "declarative",
  "view": { "type": "bar", "from": "nf", "label": "{ip}", "value": "{mbps}" }
}</code></pre>
    <p style="margin-top:12px;"><b>Templates:</b> wherever you see <span class="kbd">{field}</span>, NEURU fills in that field's value for each row. <b>Refresh</b> is how often (in seconds) it updates.</p>
  </div>

  <div class="card">
    <h2><i class="fa-solid fa-shield-halved"></i> Is this safe? (yes)</h2>
    <ul>
      <li>Widgets can only read the curated sources above — never the raw database, files, or your login/passwords.</li>
      <li>Every source checks <i>your</i> permissions, so a shared widget can't reveal anything you couldn't already see.</li>
      <li>You can delete or export any of your widgets anytime from the <b>My widgets</b> tab.</li>
    </ul>
  </div>
</div>

<script>
function copyPrompt(){
  const t=document.getElementById('ai-prompt').innerText;
  const ok=()=>{ const b=document.querySelector('.copybtn'); const o=b.innerHTML; b.innerHTML='<i class="fa-solid fa-check"></i> Copied'; setTimeout(()=>b.innerHTML=o,1500); };
  // navigator.clipboard only works on HTTPS/localhost; fall back to execCommand on plain HTTP
  if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(t).then(ok).catch(()=>fb(t,ok)); }
  else fb(t,ok);
}
function fb(t,ok){ const ta=document.createElement('textarea'); ta.value=t; ta.style.position='fixed'; ta.style.top='-9999px'; document.body.appendChild(ta); ta.focus(); ta.select();
  try{ document.execCommand('copy'); ok(); }catch(e){} document.body.removeChild(ta); }
</script>
</body></html>
