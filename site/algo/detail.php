<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/common/cache.php';

// Validate params — uuid: 6 hex chars, cat: single letter a–v
$uuid = (isset($_GET['uuid']) && preg_match('/^[0-9a-f]{6}$/', $_GET['uuid']))
    ? $_GET['uuid'] : '';
$cat  = (isset($_GET['cat'])  && preg_match('/^[a-v]$/',       $_GET['cat']))
    ? $_GET['cat']  : '';

if ($uuid === '' || $cat === '') {
    header('Location: /algo/');
    exit;
}

$cat_names = [
    'a' => 'Encoding & Checksum',   'b' => 'Hash / Digest / XOF',
    'c' => 'Password KDFs',          'd' => 'Symmetric Block Ciphers',
    'e' => 'Stream Ciphers',         'f' => 'Block Cipher Modes',
    'g' => 'AEAD Algorithms',        'h' => 'MAC Algorithms',
    'i' => 'Key Derivation Functions', 'j' => 'Key Agreement / KEM',
    'k' => 'Digital Signatures',    'l' => 'PQ Digital Signatures',
    'm' => 'Stateful Hash Signatures', 'n' => 'Threshold / MPC',
    'o' => 'Lightweight Crypto',    'p' => 'DRBG / RNG',
    'q' => 'ZK Proofs / HE',        'r' => 'Protocol Primitives',
    's' => 'PKI / Certificates',    't' => 'Hardware / HSM / TEE',
    'u' => 'Verifiable Delay Functions', 'v' => 'Advanced Primitives',
];
$cat_name = $cat_names[$cat] ?? 'Algorithm';
$safe_uuid = htmlspecialchars($uuid, ENT_QUOTES);
$safe_cat  = htmlspecialchars($cat,  ENT_QUOTES);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Algorithm detail — NextSSL cryptographic library">
  <meta name="author" content="QudsLab">
  <link rel="icon" href="<?php cprint('assets/logo_glow.svg'); ?>" type="image/svg+xml">
  <title id="page-title">Algorithm — NextSSL</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="<?php cprint('static/style.css'); ?>">
  <style>
    .det-page  { padding-top: 64px; min-height: 100vh; }
    .det-wrap  { max-width: 860px; margin: 0 auto; padding: 40px 28px 80px; }

    /* Back link */
    .det-back {
      display: inline-flex; align-items: center; gap: 6px;
      font-family: var(--font-mono); font-size: 12px;
      color: var(--slate); opacity: 0.5; text-decoration: none;
      margin-bottom: 28px; transition: opacity 0.12s;
    }
    .det-back:hover { opacity: 1; }
    .det-back svg { width: 12px; height: 12px; stroke: currentColor; stroke-width: 2.5; fill: none; }

    /* Loading / Error */
    .det-loading {
      display: flex; align-items: center; gap: 10px; padding: 80px 0;
      font-family: var(--font-mono); font-size: 13px; color: var(--slate); opacity: 0.4;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .det-spin {
      width: 18px; height: 18px; border-radius: 50%;
      border: 2px solid var(--border); border-top-color: var(--green);
      animation: spin 0.7s linear infinite; flex-shrink: 0;
    }
    .det-error {
      padding: 60px 0; text-align: center;
      font-family: var(--font-mono); font-size: 13px; color: var(--amber); opacity: 0.7;
    }

    /* ── Header block ── */
    .det-header { margin-bottom: 36px; }
    .det-breadcrumb {
      font-family: var(--font-mono); font-size: 11px;
      color: var(--slate); opacity: 0.4; margin-bottom: 10px;
    }
    .det-breadcrumb a { color: inherit; text-decoration: none; }
    .det-breadcrumb a:hover { opacity: 1; color: var(--green); }

    .det-title-row { display: flex; align-items: flex-start; gap: 14px; flex-wrap: wrap; margin-bottom: 8px; }
    .det-name {
      font-family: var(--font-mono); font-size: 30px; font-weight: 700;
      color: var(--snow); letter-spacing: -0.5px;
    }
    .det-badge {
      display: inline-flex; align-items: center;
      font-family: var(--font-mono); font-size: 11px; font-weight: 600;
      padding: 3px 9px; border-radius: 4px; border: 1px solid;
      margin-top: 6px; flex-shrink: 0;
    }
    .det-badge.active { color: var(--green); border-color: rgba(0,217,146,0.35); background: rgba(0,217,146,0.07); }
    .det-badge.legacy { color: var(--amber); border-color: rgba(227,179,65,0.35); background: rgba(227,179,65,0.07); }
    .det-badge.new    { color: var(--blue);  border-color: rgba(74,158,255,0.35);  background: rgba(74,158,255,0.07); }

    .det-subtitle {
      font-size: 16px; color: var(--slate); opacity: 0.65;
      font-style: italic; margin-bottom: 12px;
    }
    .det-meta-row {
      display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
      font-family: var(--font-mono); font-size: 11px; color: var(--slate); opacity: 0.4;
    }
    .det-meta-item { display: flex; align-items: center; gap: 5px; }
    .det-uuid {
      font-family: var(--font-mono); font-size: 11px;
      padding: 2px 8px; border: 1px solid var(--border); border-radius: 4px;
      color: var(--slate); opacity: 0.5; cursor: pointer;
      transition: border-color 0.15s, opacity 0.15s; user-select: all;
    }
    .det-uuid:hover { border-color: var(--green); opacity: 0.9; }

    /* ── Divider ── */
    .det-divider { height: 1px; background: var(--border); margin: 28px 0; }

    /* ── Section ── */
    .det-sec { margin-bottom: 32px; }
    .det-sec-title {
      font-family: var(--font-mono); font-size: 10px; font-weight: 700;
      letter-spacing: 0.12em; text-transform: uppercase;
      color: var(--slate); opacity: 0.4; margin-bottom: 10px;
    }
    .det-text {
      font-size: 14px; color: var(--slate); opacity: 0.75; line-height: 1.7;
    }

    /* Tags */
    .det-tags { display: flex; flex-wrap: wrap; gap: 6px; }
    .det-tag {
      font-family: var(--font-mono); font-size: 11px;
      padding: 3px 9px; border-radius: 4px;
      border: 1px solid var(--border);
      color: var(--slate); opacity: 0.55;
    }

    /* Two-col layout */
    .det-cols { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
    @media (max-width: 600px) { .det-cols { grid-template-columns: 1fr; } }

    /* Pros / Cons */
    .det-procon { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px; }
    .det-procon li {
      display: flex; align-items: flex-start; gap: 8px;
      font-size: 13px; color: var(--slate); opacity: 0.7; line-height: 1.5;
    }
    .det-procon li::before { flex-shrink: 0; font-weight: 700; margin-top: 1px; }
    .det-procon.pros li::before { content: '+'; color: var(--green); }
    .det-procon.cons li::before { content: '−'; color: var(--amber); }

    /* Meters */
    .det-meter-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
    .det-meter-label { font-family: var(--font-mono); font-size: 11px; color: var(--slate); opacity: 0.5; width: 80px; flex-shrink: 0; }
    .det-meter-dots  { display: flex; gap: 4px; }
    .det-dot {
      width: 8px; height: 8px; border-radius: 50%;
      border: 1px solid var(--border); background: none;
    }
    .det-dot.on-diff { background: var(--blue); border-color: var(--blue); }
    .det-dot.on-sec  { background: var(--green); border-color: var(--green); }
    .det-meter-val { font-family: var(--font-mono); font-size: 11px; color: var(--slate); opacity: 0.35; }

    /* PQ bar */
    .det-pq-row { display: flex; align-items: center; gap: 12px; }
    .det-pq-bar  { flex: 1; height: 4px; border-radius: 2px; background: var(--border); overflow: hidden; }
    .det-pq-fill { height: 100%; border-radius: 2px; background: var(--green); }
    .det-pq-label { font-family: var(--font-mono); font-size: 11px; color: var(--slate); opacity: 0.5; flex-shrink: 0; min-width: 80px; }
    .det-pq-impact { font-size: 13px; color: var(--slate); opacity: 0.6; line-height: 1.5; margin-top: 8px; }

    /* Flow steps */
    .det-flow { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
    .det-flow-step {
      font-family: var(--font-mono); font-size: 11px;
      padding: 4px 10px; border: 1px solid var(--border); border-radius: 4px;
      color: var(--slate); opacity: 0.6; white-space: nowrap;
    }
    .det-flow-arrow { color: var(--slate); opacity: 0.25; font-size: 12px; }

    /* Example block */
    .det-example { background: var(--carbon); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; }
    .det-ex-scenario { font-size: 12px; color: var(--slate); opacity: 0.5; margin-bottom: 12px; font-style: italic; }
    .det-ex-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    @media (max-width: 500px) { .det-ex-grid { grid-template-columns: 1fr; } }
    .det-ex-block-label {
      font-family: var(--font-mono); font-size: 10px; font-weight: 700;
      letter-spacing: 0.1em; text-transform: uppercase;
      color: var(--slate); opacity: 0.35; margin-bottom: 6px;
    }
    .det-ex-code {
      font-family: var(--font-mono); font-size: 11px; color: var(--green);
      word-break: break-all; line-height: 1.6;
    }

    /* Related */
    .det-related { display: flex; flex-wrap: wrap; gap: 6px; }
    .det-rel-tag {
      font-family: var(--font-mono); font-size: 11px;
      padding: 3px 10px; border-radius: 4px;
      border: 1px solid var(--border); cursor: pointer;
      color: var(--slate); opacity: 0.55; text-decoration: none;
      transition: border-color 0.12s, opacity 0.12s;
    }
    .det-rel-tag:hover { border-color: var(--green); opacity: 1; color: var(--green); }
  </style>
</head>
<body>
<?php $nav_type = 'inner'; require $_SERVER['DOCUMENT_ROOT'] . '/extension/header.php'; ?>

<div class="det-page">
  <div class="det-wrap">
    <a class="det-back" href="/algo/">
      <svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
      Back to browser
    </a>

    <div id="det-content">
      <div class="det-loading"><div class="det-spin"></div>Loading algorithm…</div>
    </div>
  </div>
</div>

<?php require $_SERVER['DOCUMENT_ROOT'] . '/extension/footer.php'; ?>

<script>
(function () {
  'use strict';

  const uuid = '<?= $safe_uuid ?>';
  const cat  = '<?= $safe_cat ?>';

  const PQ_LABELS = ['','Unsafe','Vulnerable','Transitioning','Quantum-Safe','Not Applicable'];

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function dots(val, max, cls) {
    let h = '';
    for (let i = 1; i <= max; i++) {
      h += `<span class="det-dot ${i <= val ? cls : ''}"></span>`;
    }
    return h;
  }

  function renderAlgo(a) {
    // Update page title
    document.title = `${a.title || a.name} — NextSSL`;

    const pqPct = Math.round(((a.post_quantum_status || 0) / 5) * 100);
    const pqLabel = PQ_LABELS[a.post_quantum_status] || '';

    // Build flow
    let flowHtml = '';
    if (Array.isArray(a.flow) && a.flow.length) {
      flowHtml = a.flow.map((s, i) =>
        `<span class="det-flow-step">${esc(s)}</span>${i < a.flow.length - 1 ? '<span class="det-flow-arrow">→</span>' : ''}`
      ).join('');
    }

    // Build example
    let exHtml = '';
    if (a.example && a.example.scenario) {
      const inp = a.example.input ? Object.entries(a.example.input).map(([k,v]) => `<div><span style="opacity:0.45">${esc(k)}:</span> ${esc(v)}</div>`).join('') : '';
      const out = a.example.output ? Object.entries(a.example.output).map(([k,v]) => `<div><span style="opacity:0.45">${esc(k)}:</span> ${esc(v)}</div>`).join('') : '';
      exHtml = `<div class="det-example">
        <div class="det-ex-scenario">${esc(a.example.scenario)}</div>
        <div class="det-ex-grid">
          ${inp ? `<div><div class="det-ex-block-label">Input</div><div class="det-ex-code">${inp}</div></div>` : ''}
          ${out ? `<div><div class="det-ex-block-label">Output</div><div class="det-ex-code">${out}</div></div>` : ''}
        </div>
      </div>`;
    }

    // Related
    let relHtml = '';
    if (Array.isArray(a.related) && a.related.length) {
      relHtml = `<div class="det-related">${a.related.map(r => `<a class="det-rel-tag" href="/algo/?q=${encodeURIComponent(r)}">${esc(r)}</a>`).join('')}</div>`;
    }

    const statusClass = a.status || 'active';

    document.getElementById('det-content').innerHTML = `
      <div class="det-header">
        <div class="det-breadcrumb">
          <a href="/algo/">Browser</a> / <span>${esc(a.cat || '')}</span>
        </div>
        <div class="det-title-row">
          <div class="det-name">${esc(a.title || a.name)}</div>
          <span class="det-badge ${esc(statusClass)}">${esc(statusClass)}</span>
        </div>
        ${a.mental_model ? `<div class="det-subtitle">${esc(a.mental_model)}</div>` : ''}
        <div class="det-meta-row">
          <span class="det-meta-item">Category: ${esc(a.cat || cat)}</span>
          <span class="det-meta-item">Type: ${esc(a.type || '—')}</span>
          <span class="det-uuid" title="Click to copy UUID" onclick="copyUuid(this)">${esc(uuid)}</span>
        </div>
      </div>

      <div class="det-divider"></div>

      ${a.description_md ? `<div class="det-sec">
        <div class="det-sec-title">Description</div>
        <div class="det-text">${esc(a.description_md)}</div>
      </div>` : ''}

      <div class="det-cols">
        ${Array.isArray(a.pros) && a.pros.length ? `<div class="det-sec">
          <div class="det-sec-title">Pros</div>
          <ul class="det-procon pros">${a.pros.map(p=>`<li>${esc(p)}</li>`).join('')}</ul>
        </div>` : ''}
        ${Array.isArray(a.cons) && a.cons.length ? `<div class="det-sec">
          <div class="det-sec-title">Cons</div>
          <ul class="det-procon cons">${a.cons.map(c=>`<li>${esc(c)}</li>`).join('')}</ul>
        </div>` : ''}
      </div>

      <div class="det-cols">
        ${Array.isArray(a.purpose) && a.purpose.length ? `<div class="det-sec">
          <div class="det-sec-title">Purpose</div>
          <div class="det-tags">${a.purpose.map(p=>`<span class="det-tag">${esc(p)}</span>`).join('')}</div>
        </div>` : ''}
        ${Array.isArray(a.good_for) && a.good_for.length ? `<div class="det-sec">
          <div class="det-sec-title">Good For</div>
          <div class="det-tags">${a.good_for.map(p=>`<span class="det-tag">${esc(p)}</span>`).join('')}</div>
        </div>` : ''}
      </div>

      ${Array.isArray(a.avoid_for) && a.avoid_for.length ? `<div class="det-sec">
        <div class="det-sec-title">Avoid For</div>
        <div class="det-tags">${a.avoid_for.map(p=>`<span class="det-tag" style="border-color:rgba(227,179,65,0.25);color:var(--amber);opacity:0.7">${esc(p)}</span>`).join('')}</div>
      </div>` : ''}

      <div class="det-divider"></div>

      <div class="det-cols">
        <div class="det-sec">
          <div class="det-sec-title">Metrics</div>
          <div class="det-meter-row">
            <span class="det-meter-label">Difficulty</span>
            <div class="det-meter-dots">${dots(a.difficulty||0, 10, 'on-diff')}</div>
            <span class="det-meter-val">${a.difficulty||0}/10</span>
          </div>
          <div class="det-meter-row">
            <span class="det-meter-label">Security</span>
            <div class="det-meter-dots">${dots(a.security||0, 10, 'on-sec')}</div>
            <span class="det-meter-val">${a.security||0}/10</span>
          </div>
        </div>
        <div class="det-sec">
          <div class="det-sec-title">Post-Quantum Status</div>
          <div class="det-pq-row">
            <div class="det-pq-bar"><div class="det-pq-fill" style="width:${pqPct}%"></div></div>
            <span class="det-pq-label">${esc(pqLabel)}</span>
          </div>
          ${a.quantum_impact ? `<div class="det-pq-impact">${esc(a.quantum_impact)}</div>` : ''}
        </div>
      </div>

      ${flowHtml ? `<div class="det-sec">
        <div class="det-sec-title">How It Works</div>
        <div class="det-flow">${flowHtml}</div>
      </div>` : ''}

      ${exHtml ? `<div class="det-sec">
        <div class="det-sec-title">Example</div>
        ${exHtml}
      </div>` : ''}

      ${relHtml ? `<div class="det-sec">
        <div class="det-sec-title">Related Algorithms</div>
        ${relHtml}
      </div>` : ''}
    `;
  }

  window.copyUuid = function(el) {
    navigator.clipboard.writeText(uuid).then(() => {
      const orig = el.textContent;
      el.textContent = 'copied!';
      setTimeout(() => { el.textContent = orig; }, 1200);
    }).catch(() => {});
  };

  // Fetch detail
  fetch(`/api/index.php?category=${encodeURIComponent(cat)}&algo=${encodeURIComponent(uuid)}`)
    .then(r => r.json())
    .then(json => {
      if (json.status !== 'success' || !json.data) throw new Error('Not found');
      renderAlgo(json.data);
    })
    .catch(() => {
      document.getElementById('det-content').innerHTML =
        `<div class="det-error">Algorithm not found.<br><a href="/algo/" style="color:var(--green);font-family:var(--font-mono);font-size:13px">← Back to browser</a></div>`;
    });
})();
</script>
</body>
</html>