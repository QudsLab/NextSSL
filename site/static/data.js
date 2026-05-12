// ─── Comparison Table ────────────────────────────────────────────────────────

const COMPARE_ROWS = [
    {
        feature: "Post-quantum (FIPS 203/204/205)",
        nextssl: "Full suite",
        openssl: { text: "Partial", dim: true },
        boring: { text: "Partial", dim: true },
        sodium: { text: "None", dim: true },
        wolf: { text: "Partial", dim: true },
        mbed: { text: "None", dim: true },
    },
    {
        feature: "Algorithm count",
        nextssl: "776",
        openssl: { text: "~150", dim: true },
        boring: { text: "~80", dim: true },
        sodium: { text: "~25", dim: true },
        wolf: { text: "~120", dim: true },
        mbed: { text: "~60", dim: true },
    },
    {
        feature: "ZK-friendly hashes (Poseidon, MiMC)",
        nextssl: "Yes",
        openssl: { text: "No", dim: true },
        boring: { text: "No", dim: true },
        sodium: { text: "No", dim: true },
        wolf: { text: "No", dim: true },
        mbed: { text: "No", dim: true },
    },
    {
        feature: "Threshold / MPC primitives",
        nextssl: "52 algorithms",
        openssl: { text: "None", dim: true },
        boring: { text: "None", dim: true },
        sodium: { text: "None", dim: true },
        wolf: { text: "None", dim: true },
        mbed: { text: "None", dim: true },
    },
    {
        feature: "WASM compilation target",
        nextssl: "Yes",
        openssl: { text: "Limited", dim: true },
        boring: { text: "No", dim: true },
        sodium: { text: "Yes", dim: false },
        wolf: { text: "Yes", dim: false },
        mbed: { text: "Partial", dim: true },
    },
    {
        feature: "Lightweight crypto (NIST LWC)",
        nextssl: "Full Ascon family",
        openssl: { text: "None", dim: true },
        boring: { text: "None", dim: true },
        sodium: { text: "None", dim: true },
        wolf: { text: "Partial", dim: true },
        mbed: { text: "None", dim: true },
    },
    {
        feature: "Hardware instruction auto-select",
        nextssl: "Runtime detection",
        openssl: { text: "Compile-time flags", dim: true },
        boring: { text: "Runtime", dim: false },
        sodium: { text: "Yes", dim: false },
        wolf: { text: "Partial", dim: true },
        mbed: { text: "Compile-time", dim: true },
    },
    {
        feature: "FIPS 140-3 path",
        nextssl: "Planned",
        openssl: { text: "Yes (module)", dim: false },
        boring: { text: "No", dim: true },
        sodium: { text: "No", dim: true },
        wolf: { text: "Yes", dim: false },
        mbed: { text: "Yes", dim: false },
    },
    {
        feature: "License",
        nextssl: "Apache-2.0",
        openssl: { text: "Apache-2.0", dim: false },
        boring: { text: "BSD / ISC mix", dim: false },
        sodium: { text: "ISC", dim: false },
        wolf: { text: "GPL / Commercial", dim: true },
        mbed: { text: "Apache-2.0", dim: false },
    },
    {
        feature: "Noise Protocol framework",
        nextssl: "13 patterns",
        openssl: { text: "No", dim: true },
        boring: { text: "No", dim: true },
        sodium: { text: "No", dim: true },
        wolf: { text: "No", dim: true },
        mbed: { text: "No", dim: true },
    },
    {
        feature: "Embedded / IoT optimized",
        nextssl: "Yes (LWC + WASM)",
        openssl: { text: "No", dim: true },
        boring: { text: "No", dim: true },
        sodium: { text: "Partial", dim: true },
        wolf: { text: "Yes", dim: false },
        mbed: { text: "Yes (primary focus)", dim: false },
    },
    {
        feature: "Algo Modularity (remove, add, build)",
        nextssl: "Yes (modular archive)",
        openssl: { text: "No", dim: true },
        boring: { text: "No", dim: true },
        sodium: { text: "No", dim: true },
        wolf: { text: "No", dim: true },
        mbed: { text: "No", dim: true },
    },
];

function renderCompareTable() {
    const tbody = document.getElementById('compare-tbody');
    if (!tbody) return;
    COMPARE_ROWS.forEach(row => {
        const libs = ['openssl', 'boring', 'sodium', 'wolf', 'mbed'];
        const libCells = libs.map(k =>
            `<td${row[k].dim ? ' class="dis"' : ''}>${row[k].text}</td>`
        ).join('');
        tbody.insertAdjacentHTML('beforeend',
            `<tr>
        <td class="feature-col">${row.feature}</td>
        <td class="nextssl-col">${row.nextssl}</td>
        ${libCells}
      </tr>`
        );
    });
}

// ─── Use Cases ───────────────────────────────────────────────────────────────

const USE_CASES = [
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
      <polyline points="9 22 9 12 15 12 15 22"/>
    </svg>`,
        title: "Financial and Fintech",
        body: `HSM integration via PKCS#11 3.0, FIPS 140-3 compliant algorithm selection, AES-GCM for data
      at rest, and RSA-PSS to ML-DSA migration paths with zero-downtime hybrid signing. The signing key ceremony
      happens once; NextSSL makes the migration invisible to downstream systems.`,
        tags: ["pkcs11-3.0", "aes-gcm", "rsa-pss", "ml-dsa-87", "hkdf", "fips-140-3"],
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
    </svg>`,
        title: "Blockchain and Web3",
        body: `secp256k1, BLS12-381 pairing operations, Pedersen and Poseidon hashes for circuit
      efficiency, ZK-SNARK proof generation hooks, Threshold ECDSA via FROST and GG20, ring signatures, and
      linkable ring signatures. The complete primitive set for onchain cryptography, all in C with WASM
      compilation targets.`,
        tags: ["secp256k1", "bls12-381", "poseidon", "frost", "gg20", "groth16", "plonk"],
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <rect x="2" y="7" width="20" height="14" rx="2"/>
      <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>
    </svg>`,
        title: "IoT and Embedded",
        body: `Ascon-AEAD128 (NIST LWC winner) and the full Ascon family for constrained devices, HIGHT
      and LEA for hardware-efficient block cipher operations, GIFT for ultra-low area implementations, ultra-low
      memory footprint compilation, WASM target, and ARM TrustZone integration via the TEE interface layer.`,
        tags: ["ascon-aead128", "hight", "lea", "gift", "arm-trustzone", "wasm"],
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>`,
        title: "Government and Defense",
        body: `GOST R 34.12 (Kuznyechik and Magma), SM2/SM3/SM4 Chinese national standards, ARIA (Korean
      standard), Streebog hash family, full NIST FIPS compliance surface including SP 800-131A transition roadmap,
      and certified hardware interfaces via PKCS#11 for HSMs in classified environments.`,
        tags: ["kuznyechik", "sm2", "sm3", "sm4", "aria-256", "streebog512", "gost-r-34.10-2012"],
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
    </svg>`,
        title: "Military-Grade &amp; Critical Infrastructure",
        body: `For teams operating under classified threat models or national security mandates:
      constant-time implementations resistant to timing and cache-timing attacks, TEMPEST-aware design patterns,
      CAVP-validated primitives, and a clean separation between approved and unapproved algorithm surfaces.
      NextSSL gives mission-critical deployments a single, auditable C dependency with no surprise transitive code.`,
        tags: ["constant-time", "cavp-validated", "fips-140-3", "sp-800-131a", "side-channel-resistant", "zero-deps", "pkcs11"],
    },
    {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <ellipse cx="12" cy="5" rx="9" ry="3"/>
      <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
      <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
    </svg>`,
        title: "Platform-Independent Systems &amp; Future Languages",
        body: `NextSSL is built to run everywhere: 29 pre-built binaries across Android (arm64/x86), iOS,
      WASM/WASI, Linux glibc &amp; musl, macOS universal, Windows MSVC &amp; MinGW. Future binding surfaces
      planned for Java, .NET, and Go mean that regardless of what runtime your system targets, one crypto library
      covers the full surface, today and tomorrow.`,
        tags: ["android", "ios", "wasm", "linux-musl", "win-msvc", "java-planned", ".net-planned"],
    },
];

function renderUseCases() {
    const grid = document.getElementById('usecase-grid');
    if (!grid) return;
    USE_CASES.forEach(uc => {
        const tags = uc.tags.map(t => `<span class="uc-tag">${t}</span>`).join('');
        grid.insertAdjacentHTML('beforeend',
            `<div class="usecase-card">
        <div class="uc-icon">${uc.icon}</div>
        <div class="uc-title">${uc.title}</div>
        <p class="uc-body">${uc.body}</p>
        <div class="uc-tags">${tags}</div>
      </div>`
        );
    });
}

// ─── Timeline ────────────────────────────────────────────────────────────────

const TIMELINE_ENTRIES = [
    {
        side: 'left',
        dot: 'done',
        event: {
            year: '2022 · Global',
            title: 'NIST PQC Round 3 Finalists Selected',
            body: 'CRYSTALS-Kyber, CRYSTALS-Dilithium, Falcon, and SPHINCS+ announced after four years of global cryptanalysis. The post-quantum era officially begins.',
        },
        context: {
            label: 'NextSSL Will Cover',
            tags: [
                { text: 'ML-KEM (Kyber)', cls: 'tl-tag-green' },
                { text: 'ML-DSA (Dilithium)', cls: 'tl-tag-green' },
                { text: 'SLH-DSA (SPHINCS+)', cls: 'tl-tag-green' },
                { text: 'Falcon-512 / 1024', cls: 'tl-tag-green' },
            ],
        },
    },
    {
        side: 'right',
        dot: 'done',
        event: {
            year: '2024 · Global',
            title: 'FIPS 203, 204, 205 Published',
            body: 'ML-KEM, ML-DSA, and SLH-DSA become federal standards. Deployment begins across US government infrastructure. The clock on classical crypto starts ticking.',
        },
        context: {
            label: 'Industry Impact',
            tags: [
                { text: 'FIPS 203 ✓', cls: 'tl-tag-green' },
                { text: 'FIPS 204 ✓', cls: 'tl-tag-green' },
                { text: 'FIPS 205 ✓', cls: 'tl-tag-green' },
                { text: 'Hybrid TLS 1.3' },
                { text: 'AWS, Google, Cloudflare deploy' },
            ],
        },
    },
    {
        side: 'left',
        dot: 'done',
        event: {
            year: 'Jul 2025 · NextSSL Founded',
            title: 'Project starts — first 21 algorithm surfaces mapped',
            body: 'QudsLab starts NextSSL with a clear goal: one C library for every cryptographic primitive. The first 21 algorithm surfaces are mapped and initial architecture is drafted.',
        },
        context: {
            label: 'Initial Architecture',
            tags: [
                { text: 'C99 core' },
                { text: '3 safety profiles' },
                { text: 'Multi-platform target' },
                { text: '21 algo surfaces' },
            ],
        },
    },
    {
        side: 'right',
        dot: 'done',
        event: {
            year: 'Aug-Sep 2025 · Setback',
            title: 'Phase 1 fails — restarted from scratch twice',
            body: 'The first categorization approach failed. A second attempt using algorithm ID 2 also failed. Rather than patch a flawed foundation, the team wiped and rebuilt. Every failure taught exactly what a proper taxonomy must look like.',
        },
        context: {
            label: 'Lessons Learned',
            tags: [
                { text: 'Taxonomy matters', style: 'color:#e3b341;border-color:rgba(227,179,65,0.3)' },
                { text: 'ID scheme rebuilt', style: 'color:#e3b341;border-color:rgba(227,179,65,0.3)' },
                { text: 'Restart over patch' },
            ],
        },
    },
    {
        side: 'left',
        dot: 'done',
        event: {
            year: 'Oct-Nov 2025 · Breakthrough',
            title: 'Categorization breakthrough — 22+ categories, strong ground',
            body: 'Deep research into the full cryptographic algorithm space yields a proper taxonomy: 22+ categories across classical, lightweight, post-quantum, ZK-friendly, and emerging primitives. A foundation the team is now confident can carry the full scope.',
        },
        context: {
            label: 'New Foundation',
            tags: [
                { text: '22+ categories', cls: 'tl-tag-green' },
                { text: 'Systematic taxonomy', cls: 'tl-tag-green' },
                { text: 'Hash / XOF' },
                { text: 'AEAD' },
                { text: 'PQC' },
                { text: 'ZK-friendly' },
                { text: 'MPC / Threshold' },
            ],
        },
    },
    {
        side: 'right',
        dot: 'done',
        event: {
            year: 'Dec 2025 · Archive Milestone',
            title: '776 algorithms — the most comprehensive open C crypto library',
            body: 'The algorithm archive reaches 776 entries across 22+ categories. 29 binary targets across 7 major platform families. Confident in scale: from MD2 to ML-KEM-1024, every standard ever published is mapped and categorized.',
        },
        context: {
            label: 'Scale Achieved',
            tags: [
                { text: '776 algorithms', cls: 'tl-tag-green' },
                { text: '29 binary targets', cls: 'tl-tag-green' },
                { text: '7 major platforms', cls: 'tl-tag-green' },
                { text: 'Android · iOS · WASM' },
                { text: 'Linux · macOS · Win' },
            ],
        },
    },
    {
        side: 'left',
        dot: 'current',
        event: {
            year: '2026 · Global',
            title: 'HQC selected as backup KEM — hybrid TLS accelerates',
            body: 'HQC (code-based) selected as the backup KEM alongside ML-KEM. Hybrid TLS 1.3 deployments accelerate. Post-quantum PKI tooling matures across cloud providers.',
        },
        context: {
            label: 'NextSSL Tracks',
            tags: [
                { text: 'HQC-128', cls: 'tl-tag-green' },
                { text: 'HQC-192', cls: 'tl-tag-green' },
                { text: 'HQC-256', cls: 'tl-tag-green' },
                { text: 'Hybrid TLS 1.3' },
                { text: 'MAYO · HAWK · SQISign' },
            ],
        },
    },
    {
        side: 'right',
        dot: 'future',
        event: {
            year: '2030 · Deadline',
            title: 'Classical crypto retirement — NIST SP 800-131A',
            body: 'RSA, classical ECDSA, and DSA reach retirement under NIST SP 800-131A. Systems still relying on classical key exchange will be non-compliant. The migration window closes.',
        },
        context: {
            label: 'NextSSL: Migration Ready',
            tags: [
                { text: 'RSA ← retire', style: 'color:#ff7b72;border-color:rgba(255,123,114,0.3)' },
                { text: 'ECDSA P-256 ← retire', style: 'color:#ff7b72;border-color:rgba(255,123,114,0.3)' },
                { text: 'ML-DSA ✓', cls: 'tl-tag-green' },
                { text: 'ML-KEM ✓', cls: 'tl-tag-green' },
                { text: 'Java / .NET planned' },
            ],
        },
    },
    {
        side: 'left',
        dot: 'highlight',
        highlight: true,
        event: {
            year: 'NextSSL',
            title: 'Supporting the Full Transition. From Day One.',
            body: 'Classical and post-quantum primitives run simultaneously. Hybrid mode. Migration-safe API. No forced cutover. Your codebase moves on your schedule — and NextSSL is there for every step of it.',
        },
        context: {
            label: 'Why Act Now',
            labelStyle: 'color:var(--green)',
            cardStyle: 'border-color:rgba(0,217,146,0.2)',
            body: 'Harvest-now-decrypt-later attacks are already in progress. Data encrypted today with RSA or ECDH is being collected by adversaries for future decryption. The migration window is now, not 2030. NextSSL makes the transition surgical.',
        },
    },
];

function renderTimeline() {
    const entries = document.getElementById('timeline-entries');
    if (!entries) return;
    TIMELINE_ENTRIES.forEach((e, i) => {
        const isEven = e.side === 'right';
        const tags = (e.context.tags || []).map(t => {
            const cls = t.cls ? ` class="tl-tag ${t.cls}"` : ' class="tl-tag"';
            const style = t.style ? ` style="${t.style}"` : '';
            return `<span${cls}${style}>${t.text}</span>`;
        }).join('');

        const eventCard = e.highlight
            ? `<div class="tl-highlight-card">
          <div class="tl-year" style="color:var(--green);font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">${e.event.year}</div>
          <div class="tl-title" style="color:var(--mint)">${e.event.title}</div>
          <div class="tl-body">${e.event.body}</div>
        </div>`
            : `<div class="tl-event-card">
          <div class="tl-year">${e.event.year}</div>
          <div class="tl-title">${e.event.title}</div>
          <div class="tl-body">${e.event.body}</div>
        </div>`;

        const contextCard = e.context.body
            ? `<div class="tl-context-card"${e.context.cardStyle ? ` style="${e.context.cardStyle}"` : ''}>
          <div class="tl-context-label"${e.context.labelStyle ? ` style="${e.context.labelStyle}"` : ''}>${e.context.label}</div>
          <div class="tl-context-body">${e.context.body}</div>
        </div>`
            : `<div class="tl-context-card"${e.context.cardStyle ? ` style="${e.context.cardStyle}"` : ''}>
          <div class="tl-context-label">${e.context.label}</div>
          <div class="tl-context-tags">${tags}</div>
        </div>`;

        const leftContent = isEven ? contextCard : eventCard;
        const rightContent = isEven ? eventCard : contextCard;
        const leftSlot = isEven ? 'tl-slot-context' : 'tl-slot-event';
        const rightSlot = isEven ? 'tl-slot-event' : 'tl-slot-context';

        entries.insertAdjacentHTML('beforeend',
            `<div class="tl-entry${isEven ? ' even' : ''}">
        <div class="tl-left ${leftSlot}">${leftContent}</div>
        <div class="tl-center"><div class="tl-dot ${e.dot}"></div></div>
        <div class="tl-right ${rightSlot}">${rightContent}</div>
      </div>`
        );
    });
}

// ─── Code Section ─────────────────────────────────────────────────────────────

const CODE_SNIPPETS = {
    c: {
        file: 'nextssl_kem_example.c',
        html: `<span class="cm">/* NextSSL — hybrid post-quantum key exchange */</span>
<span class="cm">/* FIPS 203 ML-KEM-768 + HKDF-SHA256 session key derivation */</span>
<span class="kw">#include</span> <span class="str">&lt;nextssl/kem.h&gt;</span>
<span class="kw">#include</span> <span class="str">&lt;nextssl/kdf.h&gt;</span>
<span class="type">nssl_kem_t</span> <span class="fn">*kem</span> = <span class="fn">nssl_kem_new</span>(<span class="num">NSSL_ML_KEM_768</span>);   <span class="cm">/* FIPS 203 */</span>
<span class="type">uint8_t</span> ct[<span class="num">NSSL_ML_KEM_768_CT_BYTES</span>];
<span class="type">uint8_t</span> ss_a[<span class="num">32</span>], ss_b[<span class="num">32</span>];
<span class="fn">nssl_kem_encap</span>(kem, ct, ss_a, peer_pubkey);        <span class="cm">/* sender   */</span>
<span class="fn">nssl_kem_decap</span>(kem, ss_b, ct, my_privkey);         <span class="cm">/* receiver */</span>
<span class="fn">nssl_hkdf_expand</span>(ss_a, <span class="num">32</span>,                         <span class="cm">/* derive session key */</span>
                 info, info_len,
                 session_key, <span class="num">32</span>,
                 <span class="num">NSSL_SHA256</span>);
<span class="fn">nssl_kem_free</span>(kem);                                <span class="cm">/* constant-time cleanup */</span>`,
    },
    py: {
        file: 'nextssl_kem_example.py',
        html: `<span class="py-cm"># NextSSL Python bindings — same primitives, ergonomic surface</span>
<span class="py-cm"># FIPS 203 ML-KEM-768 + HKDF-SHA256</span>
<span class="py-kw">from</span> nextssl <span class="py-kw">import</span> KEM, HKDF
kem = KEM(<span class="py-str">"ML-KEM-768"</span>)               <span class="py-cm"># FIPS 203</span>
ct, ss = kem.encap(peer_pubkey)       <span class="py-cm"># sender:   encapsulate</span>
ss      = kem.decap(ct, my_privkey)  <span class="py-cm"># receiver: decapsulate</span>
key = HKDF(
    ikm=ss,
    salt=<span class="py-kw">None</span>,
    info=<span class="py-str">b"nextssl-session-v1"</span>
).expand(<span class="num">32</span>)                         <span class="py-cm"># 256-bit session key</span>`,
    },
};

function renderCodeSection() {
    const wrap = document.getElementById('code-section-wrap');
    if (!wrap) return;
    wrap.innerHTML = `
    <div class="code-container">
      <div class="code-tabs">
        <button class="code-tab active" onclick="switchCodeTab('c',this)">C API</button>
        <button class="code-tab" onclick="switchCodeTab('py',this)">Python Bindings</button>
      </div>
      <div class="code-header">
        <div class="code-dots">
          <div class="code-dot"></div>
          <div class="code-dot"></div>
          <div class="code-dot"></div>
        </div>
        <div class="code-lang" id="code-lang-label">${CODE_SNIPPETS.c.file}</div>
        <button class="copy-btn" id="copy-code-btn" onclick="copyCode()">copy</button>
      </div>
      <div class="code-panel active" id="panel-c"><pre>${CODE_SNIPPETS.c.html}</pre></div>
      <div class="code-panel" id="panel-py"><pre>${CODE_SNIPPETS.py.html}</pre></div>
    </div>
    <div class="code-note" style="margin-top:16px">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <p><strong>Algorithm-explicit API:</strong> NextSSL never hides the algorithm selection behind opaque
        defaults. Every call names the primitive. When FIPS 203 becomes FIPS 204 becomes something else, your code
        reflects exactly what runs on the wire. No guessing, no surprises in an audit.</p>
    </div>`;
}

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
    renderCompareTable();
    renderUseCases();
    renderTimeline();
    renderCodeSection();
});
