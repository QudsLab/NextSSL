<?php require_once $_SERVER['DOCUMENT_ROOT'] . '/cache.php';?>
<!DOCTYPE html>
<!-- <html lang="en" data-palette="orange"> -->
<html lang="en">
</html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="NextSSL is the cryptographic library that ships both classical and post-quantum primitives in a single C dependency. No wrappers, no abstractions, no hidden defaults. One library. Every algorithm. Zero compromise.">
  <meta name="keywords" content="cryptography, post-quantum cryptography, PQC, NIST PQC, cryptographic library, C library, AES, SHA, RSA, ECDSA, ML-KEM, SLH-DSA, password hashing, key derivation functions, KDFs, authenticated encryption, AEAD, zero-knowledge proofs, SSL, TLS, security, open source, Apache-2.0">
  <meta name="author" content="QudsLab">
  <meta property="og:url" content="https://nextssl.qudslab.com">
  <meta property="og:title" content="NextSSL, One library. Every algorithm. Zero compromise.">
  <meta property="og:description" content="NextSSL is the cryptographic library that ships both classical and post-quantum primitives in a single C dependency. No wrappers, no abstractions, no hidden defaults. One library. Every algorithm. Zero compromise.">
  <meta property="og:image" content="<?php cprint('assets/og_image.png'); ?>">
  <link rel="icon" href="<?php cprint('assets/logo_glow.svg'); ?>" type="image/x-icon">
  <title>NextSSL, One library. Every algorithm. Zero compromise.</title>
  <link rel="icon" href="<?php cprint('assets/logo_glow.svg'); ?>" type="image/svg+xml">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link
    href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Roboto+Mono:wght@400;500;700&display=swap"
    rel="stylesheet">
  <script src="<?php cprint('static/algo.js'); ?>" defer></script>
  <script src="<?php cprint('static/site.js'); ?>" defer></script>
  <link rel="stylesheet"
    href="<?php cprint('static/style.css'); ?>">
</head>
<body>
  <!-- Navigation -->
  <nav>
    <div class="nav-inner">
      <a href="#hero" class="nav-logo">
        <div class="logo-mark">
          <img src="<?php cprint('assets/logo_glow.svg'); ?>" width="28"
            height="28" alt="NextSSL" style="display:block">
        </div>
        NextSSL
      </a>
      <div class="nav-links">
        <a href="#why">Why NextSSL</a>
        <a href="#algorithms">Algorithms</a>
        <a href="#timeline">Roadmap</a>
        <a href="#usecases">Use Cases</a>
        <a href="#compare">Compare</a>
      </div>
      <div class="nav-cta">
        <a href="https://github.com/QudsLab/NextSSL" target="_blank" rel="noopener" class="gh-star">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polygon
              points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
          </svg>
          Star
        </a>
        <a href="https://github.com/QudsLab/NextSSL" target="_blank" rel="noopener" class="btn-primary">GitHub</a>
      </div>
      <div class="hamburger" onclick="toggleMenu()">
        <span></span><span></span><span></span>
      </div>
    </div>
  </nav>
  <div class="mobile-menu" id="mobile-menu">
    <a href="#why" onclick="toggleMenu()">Why NextSSL</a>
    <a href="#algorithms" onclick="toggleMenu()">Algorithms</a>
    <a href="#timeline" onclick="toggleMenu()">Roadmap</a>
    <a href="#usecases" onclick="toggleMenu()">Use Cases</a>
    <a href="#compare" onclick="toggleMenu()">Compare</a>
    <a href="https://github.com/QudsLab/NextSSL" target="_blank">View on GitHub</a>
  </div>
  <!-- Hero -->
  <section id="hero">
    <canvas id="hero-canvas"></canvas>
    <div class="hero-content">
      <div class="hero-overline">Apache-2.0 / Open Source</div>
      <h1 class="hero-title">Next<span>SSL</span></h1>
      <p class="hero-sub">The cryptographic library that ships both <strong>classical</strong> and
        <strong>post-quantum</strong> primitives in a single C dependency. No wrappers, no abstractions, no hidden
        defaults.</p>
      <div class="hero-actions">
        <a href="https://github.com/QudsLab/NextSSL" target="_blank" class="btn-hero-primary">Star on GitHub</a>
        <a href="#algorithms" class="btn-hero-ghost">Explore 776 Algorithms</a>
      </div>
      <div class="hero-counters">
        <div class="counter-item">
          <span class="counter-num" data-target="776">0</span>
          <span class="counter-label">Algorithms</span>
        </div>
        <div class="counter-item">
          <span class="counter-num" data-target="22">0</span>
          <span class="counter-label">Categories</span>
        </div>
        <div class="counter-item">
          <span class="counter-num" data-target="29">0</span>
          <span class="counter-label">Binary Targets</span>
        </div>
      </div>
    </div>
  </section>
  <!-- Why NextSSL -->
  <section id="why">
    <div class="container">
      <div class="reveal">
        <div class="section-label">Why NextSSL</div>
        <h2 class="section-title">The cryptographic surface your project needs, now and in 2035</h2>
        <p class="section-sub">Security engineers spend too much time managing dependencies. NextSSL ends that.</p>
      </div>
      <div class="why-grid reveal">
        <div class="why-card">
          <div class="why-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>
          <div class="why-title">Universal Algorithm Surface</div>
          <p class="why-body">From legacy <strong>MD5</strong> to NIST-selected <strong>ML-KEM-1024</strong> and
            <strong>FIPS 205 SLH-DSA</strong>. One dependency. Every primitive your project will ever need: classical,
            lightweight, post-quantum, and zero-knowledge: all under one consistent API surface.</p>
        </div>
        <div class="why-card">
          <div class="why-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
            </svg>
          </div>
          <div class="why-title">Hardware-Accelerated by Default</div>
          <p class="why-body"><strong>AES-NI, SHA-NI, AVX2, PCLMUL, RDRAND, ARM NEON</strong>, automatically selected at
            runtime based on CPU capabilities. You write the logic; NextSSL resolves the fast path. No configuration, no
            platform flags, no surprises in production.</p>
        </div>
        <div class="why-card">
          <div class="why-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10" />
              <path d="m4.93 4.93 14.14 14.14" />
              <path d="M12 2a10 10 0 0 1 10 10" opacity="0.4" />
            </svg>
          </div>
          <div class="why-title">Post-Quantum Ready Now</div>
          <p class="why-body">Full NIST PQC suite: <strong>ML-KEM (FIPS 203)</strong>, <strong>ML-DSA (FIPS
              204)</strong>, <strong>SLH-DSA (FIPS 205)</strong>. Drop-in hybrid mode for TLS 1.3. Migration-safe API
            design means classical and post-quantum primitives run side by side with no breaking changes.</p>
        </div>
      </div>
      <!-- Language bindings strip -->
      <div class="reveal"
        style="margin-top:40px;border:1px solid var(--border);border-radius:8px;background:var(--carbon);padding:28px 32px;display:flex;flex-wrap:wrap;align-items:center;gap:24px;justify-content:space-between">
        <div style="font-size:12px;font-weight:600;letter-spacing:1.5px;text-transform:uppercase;color:var(--slate)">
          Language Bindings</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px">
          <span
            style="padding:6px 14px;border:1px solid var(--green);border-radius:4px;font-family:var(--font-mono);font-size:12px;color:var(--mint)">C
            (Core)</span>
          <span title="Planned — not yet in repo"
            style="padding:6px 14px;border:1px dashed var(--border);border-radius:4px;font-family:var(--font-mono);font-size:12px;color:var(--slate);opacity:0.65">Rust
            <span style="font-size:10px;letter-spacing:0.5px;color:var(--slate)">[planned]</span></span>
          <span title="Planned — not yet in repo"
            style="padding:6px 14px;border:1px dashed var(--border);border-radius:4px;font-family:var(--font-mono);font-size:12px;color:var(--slate);opacity:0.65">Python
            <span style="font-size:10px;letter-spacing:0.5px;color:var(--slate)">[planned]</span></span>
          <span title="Planned — not yet in repo"
            style="padding:6px 14px;border:1px dashed var(--border);border-radius:4px;font-family:var(--font-mono);font-size:12px;color:var(--slate);opacity:0.65">Go
            <span style="font-size:10px;letter-spacing:0.5px;color:var(--slate)">[planned]</span></span>
          <span title="WASM compilation target in build system"
            style="padding:6px 14px;border:1px solid var(--border);border-radius:4px;font-family:var(--font-mono);font-size:12px;color:var(--parchment)">WASM</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--slate)">
          <svg viewBox="0 0 16 16" fill="none" stroke="var(--green)" stroke-width="1.5" width="14" height="14">
            <path d="M8 1v14M1 8h14" stroke-linecap="round" />
          </svg>
          Active development, algorithm surfaces being finalized
        </div>
      </div>
    </div>
  </section>
  <!-- Bento Feature Grid -->
  <section id="bento">
    <div class="container">
      <div class="reveal">
        <div class="section-label">What Makes NextSSL Different</div>
        <h2 class="section-title">Built different. By design.</h2>
        <p class="section-sub">Six properties that separate NextSSL from every other cryptographic library in production
          today.</p>
      </div>
      <div class="bento-grid reveal">
        <!-- Large card: Profile system -->
        <div class="bento-card bento-large">
          <div class="bento-card-label">Profile System</div>
          <div class="bento-card-title">Three audiences. One library. No compromises.</div>
          <div class="bento-card-body">NextSSL ships with three built-in safety profiles. Normal users get conservative
            defaults. Builders get all the ecosystem algorithms. Researchers get the full archive with experimental
            surfaces. You choose the profile; the library enforces it.</div>
          <div class="bento-profile-pills">
            <div class="bento-profile-pill safest">
              <span>●</span>
              <span><strong>safest-main</strong>: argon2id, xchacha20-poly1305, ed25519, x25519</span>
            </div>
            <div class="bento-profile-pill useful">
              <span>●</span>
              <span><strong>useful</strong>: PKCS#11, RSA-PSS, ECDSA, legacy KDFs, wallet primitives</span>
            </div>
            <div class="bento-profile-pill research">
              <span>●</span>
              <span><strong>research</strong>: MAYO, HAWK, Poseidon, ZK circuits, experimental AEAD</span>
            </div>
          </div>
          <svg class="bento-accent" width="160" height="160" viewBox="0 0 160 160">
            <circle cx="80" cy="80" r="70" fill="none" stroke="#00d992" stroke-width="1" />
            <circle cx="80" cy="80" r="50" fill="none" stroke="#00d992" stroke-width="1" />
            <circle cx="80" cy="80" r="30" fill="none" stroke="#00d992" stroke-width="1" />
          </svg>
        </div>
        <!-- Tall card: Archive scale -->
        <div class="bento-card bento-tall">
          <div class="bento-card-label">Archive Scale</div>
          <div class="bento-stat">776</div>
          <div class="bento-stat-label">algorithms in 22 categories</div>
          <div class="bento-card-body" style="margin-top:16px">From MD2 to ML-KEM-1024. Every standard ever published,
            plus emerging candidates. The only dependency your security layer will ever need.</div>
          <div class="bento-tags" style="margin-top:16px">
            <span class="bento-tag green">Hash / XOF</span>
            <span class="bento-tag green">PQC</span>
            <span class="bento-tag green">AEAD</span>
            <span class="bento-tag">Threshold MPC</span>
            <span class="bento-tag">ZK-friendly</span>
            <span class="bento-tag">LWC / IoT</span>
            <span class="bento-tag">Noise Protocol</span>
            <span class="bento-tag">VDF</span>
            <span class="bento-tag">PKI / HSM</span>
            <span class="bento-tag">Password KDFs</span>
            <span class="bento-tag">Stream Ciphers</span>
            <span class="bento-tag">Block Modes</span>
          </div>
        </div>
        <!-- Card: Runtime CPU dispatch -->
        <div class="bento-card">
          <div class="bento-card-label">Hardware Acceleration</div>
          <div class="bento-card-title">Runtime CPU dispatch, zero config</div>
          <div class="bento-card-body">NextSSL probes your CPU at startup and selects the fastest available path
            automatically.</div>
          <div class="bento-dispatch-grid">
            <div class="bento-dispatch-item"><span
                style="width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0;display:inline-block"></span>AES-NI
            </div>
            <div class="bento-dispatch-item"><span
                style="width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0;display:inline-block"></span>SHA-NI
            </div>
            <div class="bento-dispatch-item"><span
                style="width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0;display:inline-block"></span>AVX2
            </div>
            <div class="bento-dispatch-item"><span
                style="width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0;display:inline-block"></span>PCLMUL
            </div>
            <div class="bento-dispatch-item"><span
                style="width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0;display:inline-block"></span>ARM
              NEON</div>
            <div class="bento-dispatch-item"><span
                style="width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0;display:inline-block"></span>RDRAND
            </div>
          </div>
        </div>
        <!-- Card: Algorithm-explicit API -->
        <div class="bento-card">
          <div class="bento-card-label">API Design</div>
          <div class="bento-card-title">Algorithm-explicit. No hidden defaults.</div>
          <div class="bento-card-body">Every call names the primitive. Nothing is hidden behind opaque identifiers.
            Auditors see exactly what runs on the wire.</div>
          <div class="bento-mini-code">
            <span class="kw">nssl_kem_t</span> *kem = <span class="fn">nssl_kem_new</span>(<span
              class="num">NSSL_ML_KEM_768</span>);<br>
            <span class="fn">nssl_kem_encap</span>(kem, ct, ss, peer_pk);<br>
            <span class="fn">nssl_hkdf_expand</span>(ss, <span class="num">32</span>, info, <span class="num">12</span>,
            key, <span class="num">32</span>,<br>
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span
              class="num">NSSL_SHA256</span>);
          </div>
        </div>
        <!-- Card: Zero external deps -->
        <div class="bento-card">
          <div class="bento-card-label">Dependency Model</div>
          <div class="bento-stat" style="font-size:56px">1</div>
          <div class="bento-stat-label">dependency. this library, nothing else</div>
          <div class="bento-card-body" style="margin-top:12px">No OpenSSL. No libsodium. No vendored submodules pulling
            in unknown transitive code. One repo. One audit surface.</div>
        </div>
        <!-- Card: Constant-time + lifecycle -->
        <div class="bento-card">
          <div class="bento-card-label">Safety Labels</div>
          <div class="bento-card-title">Every algorithm carries a lifecycle label</div>
          <div class="bento-card-body">Safety decisions are visible and machine-readable, not buried in changelogs.
          </div>
          <div class="bento-tags" style="margin-top:14px">
            <span class="bento-tag green">recommended</span>
            <span class="bento-tag" style="color:#e3b341;border-color:rgba(227,179,65,0.3)">legacy</span>
            <span class="bento-tag" style="color:#ff7b72;border-color:rgba(255,123,114,0.3)">deprecated</span>
            <span class="bento-tag green">pqc</span>
            <span class="bento-tag">hybrid-ready</span>
            <span class="bento-tag">constant-time-required</span>
            <span class="bento-tag" style="color:#e3b341;border-color:rgba(227,179,65,0.3)">research</span>
            <span class="bento-tag">archive-only</span>
          </div>
        </div>
        <!-- Card: Constant-time guarantees -->
        <div class="bento-card">
          <div class="bento-card-label">Constant-Time</div>
          <div class="bento-card-title">Side-channel resistant by default</div>
          <div class="bento-card-body">Critical paths — key comparisons, secret-dependent branches, modular
            exponentiation — are written in verified constant-time idioms. No timing oracle. No Meltdown shortcut. Every
            sensitive operation reviewed against Valgrind ctgrind and compiler barriers.</div>
          <svg class="bento-accent" width="120" height="120" viewBox="0 0 120 120">
            <rect x="10" y="10" width="100" height="100" rx="8" fill="none" stroke="#00d992" stroke-width="1" />
            <line x1="10" y1="60" x2="110" y2="60" stroke="#00d992" stroke-width="1" />
            <line x1="60" y1="10" x2="60" y2="110" stroke="#00d992" stroke-width="1" />
          </svg>
        </div>
        <!-- Card: Platform targets — wide (spans 2 cols to fill the last row) -->
        <div class="bento-card bento-wide">
          <div class="bento-card-label">Platform Coverage</div>
          <div class="bento-card-title">29 binary targets. 7 platform families. One source.</div>
          <div class="bento-card-body">Every target pre-built and CI-tested on every merge. Drop in for your platform —
            no cross-compile setup required.</div>
          <div style="margin-top:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:6px">
            <div class="bento-dispatch-item"
              style="flex-direction:column;align-items:flex-start;gap:4px;padding:10px 12px">
              <span
                style="font-size:10px;color:var(--green);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:2px">Android
                &middot; 4</span>
              <span style="font-size:10px;color:var(--slate)">arm64-v8a &middot; armeabi-v7a &middot; x86 &middot;
                x86_64</span>
            </div>
            <div class="bento-dispatch-item"
              style="flex-direction:column;align-items:flex-start;gap:4px;padding:10px 12px">
              <span
                style="font-size:10px;color:var(--green);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:2px">iOS
                &middot; 3</span>
              <span style="font-size:10px;color:var(--slate)">device-arm64 &middot; sim-arm64 &middot; sim-x86_64</span>
            </div>
            <div class="bento-dispatch-item"
              style="flex-direction:column;align-items:flex-start;gap:4px;padding:10px 12px">
              <span
                style="font-size:10px;color:var(--green);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:2px">Linux
                glibc &middot; 8</span>
              <span style="font-size:10px;color:var(--slate)">x86_64 &middot; x86 &middot; arm64 &middot; armv7 &middot;
                riscv64 &middot; ppc64le &middot; s390x &middot; loongarch64</span>
            </div>
            <div class="bento-dispatch-item"
              style="flex-direction:column;align-items:flex-start;gap:4px;padding:10px 12px">
              <span
                style="font-size:10px;color:var(--green);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:2px">Linux
                musl &middot; 3</span>
              <span style="font-size:10px;color:var(--slate)">x86_64 &middot; arm64 &middot; armv7</span>
            </div>
            <div class="bento-dispatch-item"
              style="flex-direction:column;align-items:flex-start;gap:4px;padding:10px 12px">
              <span
                style="font-size:10px;color:var(--green);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:2px">macOS
                &middot; 3</span>
              <span style="font-size:10px;color:var(--slate)">arm64 &middot; x86_64 &middot; universal</span>
            </div>
            <div class="bento-dispatch-item"
              style="flex-direction:column;align-items:flex-start;gap:4px;padding:10px 12px">
              <span
                style="font-size:10px;color:var(--green);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:2px">WASM
                &middot; 2</span>
              <span style="font-size:10px;color:var(--slate)">emscripten-wasm32 &middot; wasi-wasm32</span>
            </div>
            <div class="bento-dispatch-item"
              style="flex-direction:column;align-items:flex-start;gap:4px;padding:10px 12px;grid-column:span 1">
              <span
                style="font-size:10px;color:var(--green);font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:2px">Windows
                &middot; 6</span>
              <span style="font-size:10px;color:var(--slate)">x86_64-msvc &middot; x86_64-mingw &middot; x86-msvc
                &middot; x86-mingw &middot; arm64-msvc &middot; armv7-msvc</span>
            </div>
          </div>
        </div>
        <!-- Card: ACVP test vectors -->
        <div class="bento-card">
          <div class="bento-card-label">Test Coverage</div>
          <div class="bento-card-title">ACVP &amp; NIST test vectors for every primitive</div>
          <div class="bento-card-body">NIST Automated Cryptographic Validation Protocol (ACVP) vectors run on every CI
            build. No shipping code without passing the official reference corpus — from AES-128-ECB to ML-KEM-1024
            encapsulation.</div>
          <div class="bento-mini-code" style="margin-top:14px">
            <span class="cm"># ACVP server integration</span><br>
            vectors/<span class="str">SHA3-256</span> ✓ <span class="num">1 247</span> test cases<br>
            vectors/<span class="str">ML-KEM-768</span> ✓ <span class="num">3 000</span> KATs<br>
            vectors/<span class="str">AES-GCM</span> ✓ <span class="num">4 512</span> encryptions
          </div>
        </div>
      </div>
    </div>
  </section>
  <!-- Algorithm Browser -->
  <section id="algorithms">
    <div class="container">
      <div class="reveal">
        <div class="section-label">Algorithm Browser</div>
        <h2 class="section-title">776 algorithms across 22 categories</h2>
        <p class="section-sub">The most comprehensive cryptographic algorithm surface available in a single open-source
          C library.</p>
      </div>
      <div style="margin-top:48px" class="reveal">
        <!-- Category pill grid (all categories visible, wrapping) -->
        <div class="cat-pill-grid" id="cat-tabs"></div>
        <!-- Controls -->
        <div class="browser-controls">
          <div class="search-wrap">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.35-4.35" />
            </svg>
            <input type="text" id="algo-search" placeholder="Search algorithms...">
          </div>
          <div class="filter-pills">
            <button class="pill active" data-status="all">All</button>
            <button class="pill" data-status="active">Active</button>
            <button class="pill" data-status="legacy">Legacy</button>
            <button class="pill" data-status="new">Emerging</button>
          </div>
        </div>
        <!-- Table -->
        <div class="algo-section-wrap">
          <div class="algo-table-shell">
            <div class="algo-table-wrap">
              <table class="algo-table">
                <thead>
                  <tr>
                    <th>Algorithm</th>
                    <th>Status</th>
                    <th>Category</th>
                    <th>Surface</th>
                  </tr>
                </thead>
                <tbody id="algo-tbody"></tbody>
              </table>
            </div>
            <div class="algo-table-footer">
              <div class="count-display" id="count-display">Showing <strong>1</strong> to <strong>10</strong> of
                <strong>776</strong> algorithms</div>
              <div class="pagination" id="pagination"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
  <!-- Timeline -->
  <section id="timeline">
    <div class="container">
      <div class="reveal">
        <div class="section-label">Project History &amp; PQC Timeline</div>
        <h2 class="section-title">Built in the eye of the storm</h2>
        <p class="section-sub">NextSSL was founded as NIST finalized the post-quantum era. Every milestone — including
          the failures — shaped what it is today.</p>
      </div>
      <div class="timeline-wrap reveal">
        <div class="timeline-line"></div>
        <div class="timeline-entries">
          <!-- 1: 2022 — NIST PQC Finalists -->
          <div class="tl-entry">
            <div class="tl-left tl-slot-event">
              <div class="tl-event-card">
                <div class="tl-year">2022 · Global</div>
                <div class="tl-title">NIST PQC Round 3 Finalists Selected</div>
                <div class="tl-body">CRYSTALS-Kyber, CRYSTALS-Dilithium, Falcon, and SPHINCS+ announced after four years
                  of global cryptanalysis. The post-quantum era officially begins.</div>
              </div>
            </div>
            <div class="tl-center">
              <div class="tl-dot done"></div>
            </div>
            <div class="tl-right tl-slot-context">
              <div class="tl-context-card">
                <div class="tl-context-label">NextSSL Will Cover</div>
                <div class="tl-context-tags">
                  <span class="tl-tag tl-tag-green">ML-KEM (Kyber)</span>
                  <span class="tl-tag tl-tag-green">ML-DSA (Dilithium)</span>
                  <span class="tl-tag tl-tag-green">SLH-DSA (SPHINCS+)</span>
                  <span class="tl-tag tl-tag-green">Falcon-512 / 1024</span>
                </div>
              </div>
            </div>
          </div>
          <!-- 2: 2024 — FIPS Published -->
          <div class="tl-entry even">
            <div class="tl-right tl-slot-event">
              <div class="tl-event-card">
                <div class="tl-year">2024 · Global</div>
                <div class="tl-title">FIPS 203, 204, 205 Published</div>
                <div class="tl-body">ML-KEM, ML-DSA, and SLH-DSA become federal standards. Deployment begins across US
                  government infrastructure. The clock on classical crypto starts ticking.</div>
              </div>
            </div>
            <div class="tl-center">
              <div class="tl-dot done"></div>
            </div>
            <div class="tl-left tl-slot-context">
              <div class="tl-context-card">
                <div class="tl-context-label">Industry Impact</div>
                <div class="tl-context-tags">
                  <span class="tl-tag tl-tag-green">FIPS 203 ✓</span>
                  <span class="tl-tag tl-tag-green">FIPS 204 ✓</span>
                  <span class="tl-tag tl-tag-green">FIPS 205 ✓</span>
                  <span class="tl-tag">Hybrid TLS 1.3</span>
                  <span class="tl-tag">AWS, Google, Cloudflare deploy</span>
                </div>
              </div>
            </div>
          </div>
          <!-- 3: Jul 2025 — Founded -->
          <div class="tl-entry">
            <div class="tl-left tl-slot-event">
              <div class="tl-event-card">
                <div class="tl-year">Jul 2025 · NextSSL Founded</div>
                <div class="tl-title">Project starts — first 21 algorithm surfaces mapped</div>
                <div class="tl-body">QudsLab starts NextSSL with a clear goal: one C library for every cryptographic
                  primitive. The first 21 algorithm surfaces are mapped and initial architecture is drafted.</div>
              </div>
            </div>
            <div class="tl-center">
              <div class="tl-dot done"></div>
            </div>
            <div class="tl-right tl-slot-context">
              <div class="tl-context-card">
                <div class="tl-context-label">Initial Architecture</div>
                <div class="tl-context-tags">
                  <span class="tl-tag">C99 core</span>
                  <span class="tl-tag">3 safety profiles</span>
                  <span class="tl-tag">Multi-platform target</span>
                  <span class="tl-tag">21 algo surfaces</span>
                </div>
              </div>
            </div>
          </div>
          <!-- 4: Aug-Sep 2025 — First Setback -->
          <div class="tl-entry even">
            <div class="tl-right tl-slot-event">
              <div class="tl-event-card">
                <div class="tl-year">Aug-Sep 2025 · Setback</div>
                <div class="tl-title">Phase 1 fails — restarted from scratch twice</div>
                <div class="tl-body">The first categorization approach failed. A second attempt using algorithm ID 2
                  also failed. Rather than patch a flawed foundation, the team wiped and rebuilt. Every failure taught
                  exactly what a proper taxonomy must look like.</div>
              </div>
            </div>
            <div class="tl-center">
              <div class="tl-dot done"></div>
            </div>
            <div class="tl-left tl-slot-context">
              <div class="tl-context-card">
                <div class="tl-context-label">Lessons Learned</div>
                <div class="tl-context-tags">
                  <span class="tl-tag" style="color:#e3b341;border-color:rgba(227,179,65,0.3)">Taxonomy matters</span>
                  <span class="tl-tag" style="color:#e3b341;border-color:rgba(227,179,65,0.3)">ID scheme rebuilt</span>
                  <span class="tl-tag">Restart over patch</span>
                </div>
              </div>
            </div>
          </div>
          <!-- 5: Oct-Nov 2025 — Breakthrough -->
          <div class="tl-entry">
            <div class="tl-left tl-slot-event">
              <div class="tl-event-card">
                <div class="tl-year">Oct-Nov 2025 · Breakthrough</div>
                <div class="tl-title">Categorization breakthrough — 22+ categories, strong ground</div>
                <div class="tl-body">Deep research into the full cryptographic algorithm space yields a proper taxonomy:
                  22+ categories across classical, lightweight, post-quantum, ZK-friendly, and emerging primitives. A
                  foundation the team is now confident can carry the full scope.</div>
              </div>
            </div>
            <div class="tl-center">
              <div class="tl-dot done"></div>
            </div>
            <div class="tl-right tl-slot-context">
              <div class="tl-context-card">
                <div class="tl-context-label">New Foundation</div>
                <div class="tl-context-tags">
                  <span class="tl-tag tl-tag-green">22+ categories</span>
                  <span class="tl-tag tl-tag-green">Systematic taxonomy</span>
                  <span class="tl-tag">Hash / XOF</span>
                  <span class="tl-tag">AEAD</span>
                  <span class="tl-tag">PQC</span>
                  <span class="tl-tag">ZK-friendly</span>
                  <span class="tl-tag">MPC / Threshold</span>
                </div>
              </div>
            </div>
          </div>
          <!-- 6: Dec 2025 — Archive Milestone -->
          <div class="tl-entry even">
            <div class="tl-right tl-slot-event">
              <div class="tl-event-card">
                <div class="tl-year">Dec 2025 · Archive Milestone</div>
                <div class="tl-title">776 algorithms — the most comprehensive open C crypto library</div>
                <div class="tl-body">The algorithm archive reaches 776 entries across 22+ categories. 29 binary targets
                  across 7 major platform families. Confident in scale: from MD2 to ML-KEM-1024, every standard ever
                  published is mapped and categorized.</div>
              </div>
            </div>
            <div class="tl-center">
              <div class="tl-dot done"></div>
            </div>
            <div class="tl-left tl-slot-context">
              <div class="tl-context-card">
                <div class="tl-context-label">Scale Achieved</div>
                <div class="tl-context-tags">
                  <span class="tl-tag tl-tag-green">776 algorithms</span>
                  <span class="tl-tag tl-tag-green">29 binary targets</span>
                  <span class="tl-tag tl-tag-green">7 major platforms</span>
                  <span class="tl-tag">Android · iOS · WASM</span>
                  <span class="tl-tag">Linux · macOS · Win</span>
                </div>
              </div>
            </div>
          </div>
          <!-- 7: 2026 — HQC + Implementation -->
          <div class="tl-entry">
            <div class="tl-left tl-slot-event">
              <div class="tl-event-card">
                <div class="tl-year">2026 · Global</div>
                <div class="tl-title">HQC selected as backup KEM — hybrid TLS accelerates</div>
                <div class="tl-body">HQC (code-based) selected as the backup KEM alongside ML-KEM. Hybrid TLS 1.3
                  deployments accelerate. Post-quantum PKI tooling matures across cloud providers.</div>
              </div>
            </div>
            <div class="tl-center">
              <div class="tl-dot current"></div>
            </div>
            <div class="tl-right tl-slot-context">
              <div class="tl-context-card">
                <div class="tl-context-label">NextSSL Tracks</div>
                <div class="tl-context-tags">
                  <span class="tl-tag tl-tag-green">HQC-128</span>
                  <span class="tl-tag tl-tag-green">HQC-192</span>
                  <span class="tl-tag tl-tag-green">HQC-256</span>
                  <span class="tl-tag">Hybrid TLS 1.3</span>
                  <span class="tl-tag">MAYO · HAWK · SQISign</span>
                </div>
              </div>
            </div>
          </div>
          <!-- 8: 2030 — Classical Retirement -->
          <div class="tl-entry even">
            <div class="tl-right tl-slot-event">
              <div class="tl-event-card">
                <div class="tl-year">2030 · Deadline</div>
                <div class="tl-title">Classical crypto retirement — NIST SP 800-131A</div>
                <div class="tl-body">RSA, classical ECDSA, and DSA reach retirement under NIST SP 800-131A. Systems
                  still relying on classical key exchange will be non-compliant. The migration window closes.</div>
              </div>
            </div>
            <div class="tl-center">
              <div class="tl-dot future"></div>
            </div>
            <div class="tl-left tl-slot-context">
              <div class="tl-context-card">
                <div class="tl-context-label">NextSSL: Migration Ready</div>
                <div class="tl-context-tags">
                  <span class="tl-tag" style="color:#ff7b72;border-color:rgba(255,123,114,0.3)">RSA ← retire</span>
                  <span class="tl-tag" style="color:#ff7b72;border-color:rgba(255,123,114,0.3)">ECDSA P-256 ←
                    retire</span>
                  <span class="tl-tag tl-tag-green">ML-DSA ✓</span>
                  <span class="tl-tag tl-tag-green">ML-KEM ✓</span>
                  <span class="tl-tag">Java / .NET planned</span>
                </div>
              </div>
            </div>
          </div>
          <!-- 9: NextSSL highlight -->
          <div class="tl-entry">
            <div class="tl-left tl-slot-event">
              <div class="tl-highlight-card">
                <div class="tl-year"
                  style="color:var(--green);font-family:var(--font-mono);font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">
                  NextSSL</div>
                <div class="tl-title" style="color:var(--mint)">Supporting the Full Transition. From Day One.</div>
                <div class="tl-body">Classical and post-quantum primitives run simultaneously. Hybrid mode.
                  Migration-safe API. No forced cutover. Your codebase moves on your schedule — and NextSSL is there for
                  every step of it.</div>
              </div>
            </div>
            <div class="tl-center">
              <div class="tl-dot highlight"></div>
            </div>
            <div class="tl-right tl-slot-context">
              <div class="tl-context-card" style="border-color:rgba(0,217,146,0.2)">
                <div class="tl-context-label" style="color:var(--green)">Why Act Now</div>
                <div class="tl-context-body">Harvest-now-decrypt-later attacks are already in progress. Data encrypted
                  today with RSA or ECDH is being collected by adversaries for future decryption. The migration window
                  is now, not 2030. NextSSL makes the transition surgical.</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
  <!-- Use Cases -->
  <section id="usecases">
    <div class="container">
      <div class="reveal">
        <div class="section-label">Use Cases</div>
        <h2 class="section-title">Built for the teams who can't afford to get it wrong</h2>
        <p class="section-sub">NextSSL is designed for production environments where cryptographic correctness is
          non-negotiable.</p>
      </div>
      <div class="usecase-grid reveal">
        <div class="usecase-card">
          <div class="uc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
              <polyline points="9 22 9 12 15 12 15 22" />
            </svg>
          </div>
          <div class="uc-title">Financial and Fintech</div>
          <p class="uc-body">HSM integration via PKCS#11 3.0, FIPS 140-3 compliant algorithm selection, AES-GCM for data
            at rest, and RSA-PSS to ML-DSA migration paths with zero-downtime hybrid signing. The signing key ceremony
            happens once; NextSSL makes the migration invisible to downstream systems.</p>
          <div class="uc-tags">
            <span class="uc-tag">pkcs11-3.0</span>
            <span class="uc-tag">aes-gcm</span>
            <span class="uc-tag">rsa-pss</span>
            <span class="uc-tag">ml-dsa-87</span>
            <span class="uc-tag">hkdf</span>
            <span class="uc-tag">fips-140-3</span>
          </div>
        </div>
        <div class="usecase-card">
          <div class="uc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
            </svg>
          </div>
          <div class="uc-title">Blockchain and Web3</div>
          <p class="uc-body">secp256k1, BLS12-381 pairing operations, Pedersen and Poseidon hashes for circuit
            efficiency, ZK-SNARK proof generation hooks, Threshold ECDSA via FROST and GG20, ring signatures, and
            linkable ring signatures. The complete primitive set for onchain cryptography, all in C with WASM
            compilation targets.</p>
          <div class="uc-tags">
            <span class="uc-tag">secp256k1</span>
            <span class="uc-tag">bls12-381</span>
            <span class="uc-tag">poseidon</span>
            <span class="uc-tag">frost</span>
            <span class="uc-tag">gg20</span>
            <span class="uc-tag">groth16</span>
            <span class="uc-tag">plonk</span>
          </div>
        </div>
        <div class="usecase-card">
          <div class="uc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <rect x="2" y="7" width="20" height="14" rx="2" />
              <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
            </svg>
          </div>
          <div class="uc-title">IoT and Embedded</div>
          <p class="uc-body">Ascon-AEAD128 (NIST LWC winner) and the full Ascon family for constrained devices, HIGHT
            and LEA for hardware-efficient block cipher operations, GIFT for ultra-low area implementations, ultra-low
            memory footprint compilation, WASM target, and ARM TrustZone integration via the TEE interface layer.</p>
          <div class="uc-tags">
            <span class="uc-tag">ascon-aead128</span>
            <span class="uc-tag">hight</span>
            <span class="uc-tag">lea</span>
            <span class="uc-tag">gift</span>
            <span class="uc-tag">arm-trustzone</span>
            <span class="uc-tag">wasm</span>
          </div>
        </div>
        <div class="usecase-card">
          <div class="uc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div class="uc-title">Government and Defense</div>
          <p class="uc-body">GOST R 34.12 (Kuznyechik and Magma), SM2/SM3/SM4 Chinese national standards, ARIA (Korean
            standard), Streebog hash family, full NIST FIPS compliance surface including SP 800-131A transition roadmap,
            and certified hardware interfaces via PKCS#11 for HSMs in classified environments.</p>
          <div class="uc-tags">
            <span class="uc-tag">kuznyechik</span>
            <span class="uc-tag">sm2</span>
            <span class="uc-tag">sm3</span>
            <span class="uc-tag">sm4</span>
            <span class="uc-tag">aria-256</span>
            <span class="uc-tag">streebog512</span>
            <span class="uc-tag">gost-r-34.10-2012</span>
          </div>
        </div>
        <div class="usecase-card">
          <div class="uc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path
                d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
            </svg>
          </div>
          <div class="uc-title">Military-Grade &amp; Critical Infrastructure</div>
          <p class="uc-body">For teams operating under classified threat models or national security mandates:
            constant-time implementations resistant to timing and cache-timing attacks, TEMPEST-aware design patterns,
            CAVP-validated primitives, and a clean separation between approved and unapproved algorithm surfaces.
            NextSSL gives mission-critical deployments a single, auditable C dependency with no surprise transitive
            code.</p>
          <div class="uc-tags">
            <span class="uc-tag">constant-time</span>
            <span class="uc-tag">cavp-validated</span>
            <span class="uc-tag">fips-140-3</span>
            <span class="uc-tag">sp-800-131a</span>
            <span class="uc-tag">side-channel-resistant</span>
            <span class="uc-tag">zero-deps</span>
            <span class="uc-tag">pkcs11</span>
          </div>
        </div>
        <div class="usecase-card">
          <div class="uc-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <ellipse cx="12" cy="5" rx="9" ry="3" />
              <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
              <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
            </svg>
          </div>
          <div class="uc-title">Platform-Independent Systems &amp; Future Languages</div>
          <p class="uc-body">NextSSL is built to run everywhere: 29 pre-built binaries across Android (arm64/x86), iOS,
            WASM/WASI, Linux glibc &amp; musl, macOS universal, Windows MSVC &amp; MinGW. Future binding surfaces
            planned for Java, .NET, and Go mean that regardless of what runtime your system targets, one crypto library
            covers the full surface, today and tomorrow.</p>
          <div class="uc-tags">
            <span class="uc-tag">android</span>
            <span class="uc-tag">ios</span>
            <span class="uc-tag">wasm</span>
            <span class="uc-tag">linux-musl</span>
            <span class="uc-tag">win-msvc</span>
            <span class="uc-tag">java-planned</span>
            <span class="uc-tag">.net-planned</span>
          </div>
        </div>
      </div>
    </div>
  </section>
  <!-- Code Section -->
  <section id="code">
    <div class="container">
      <div class="reveal">
        <div class="section-label">API Design</div>
        <h2 class="section-title">Eight lines to a post-quantum key exchange</h2>
        <p class="section-sub">The API is designed for clarity. Primitives are explicit; no algorithm-hiding abstraction
          layers that obscure what's happening on the wire.</p>
      </div>
      <div style="margin-top:48px" class="reveal">
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
            <div class="code-lang" id="code-lang-label">nextssl_kem_example.c</div>
            <button class="copy-btn" id="copy-code-btn" onclick="copyCode()">copy</button>
          </div>
          <div class="code-panel active" id="panel-c">
            <pre><span class="cm">/* NextSSL — hybrid post-quantum key exchange */</span>
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
<span class="fn">nssl_kem_free</span>(kem);                                <span class="cm">/* constant-time cleanup */</span></pre>
          </div>
          <div class="code-panel" id="panel-py">
            <pre><span class="py-cm"># NextSSL Python bindings — same primitives, ergonomic surface</span>
<span class="py-cm"># FIPS 203 ML-KEM-768 + HKDF-SHA256</span>
<span class="py-kw">from</span> nextssl <span class="py-kw">import</span> KEM, HKDF
kem = KEM(<span class="py-str">"ML-KEM-768"</span>)               <span class="py-cm"># FIPS 203</span>
ct, ss = kem.encap(peer_pubkey)       <span class="py-cm"># sender:   encapsulate</span>
ss      = kem.decap(ct, my_privkey)  <span class="py-cm"># receiver: decapsulate</span>
key = HKDF(
    ikm=ss,
    salt=<span class="py-kw">None</span>,
    info=<span class="py-str">b"nextssl-session-v1"</span>
).expand(<span class="num">32</span>)                         <span class="py-cm"># 256-bit session key</span></pre>
          </div>
        </div>
        <div class="code-note" style="margin-top:16px">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <p><strong>Algorithm-explicit API:</strong> NextSSL never hides the algorithm selection behind opaque
            defaults. Every call names the primitive. When FIPS 203 becomes FIPS 204 becomes something else, your code
            reflects exactly what runs on the wire. No guessing, no surprises in an audit.</p>
        </div>
      </div>
    </div>
  </section>
  <!-- Comparison -->
  <section id="compare">
    <div class="container">
      <div class="reveal">
        <div class="section-label">Honest Comparison</div>
        <h2 class="section-title">How NextSSL compares to the alternatives</h2>
        <p class="section-sub">No spin. The comparison table reflects what each library actually supports today.</p>
      </div>
      <div class="compare-wrap reveal">
        <table class="compare-table">
          <thead>
            <tr>
              <th>Feature</th>
              <th class="nextssl-col highlight">NextSSL</th>
              <th>OpenSSL 3.x</th>
              <th>BoringSSL</th>
              <th>libsodium</th>
              <th>wolfSSL</th>
              <th>mbedTLS</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td class="feature-col">Post-quantum (FIPS 203/204/205)</td>
              <td class="nextssl-col">Full suite</td>
              <td class="dis">Partial</td>
              <td class="dis">Partial</td>
              <td class="dis">None</td>
              <td class="dis">Partial</td>
              <td class="dis">None</td>
            </tr>
            <tr>
              <td class="feature-col">Algorithm count</td>
              <td class="nextssl-col">776</td>
              <td class="dis">~150</td>
              <td class="dis">~80</td>
              <td class="dis">~25</td>
              <td class="dis">~120</td>
              <td class="dis">~60</td>
            </tr>
            <tr>
              <td class="feature-col">ZK-friendly hashes (Poseidon, MiMC)</td>
              <td class="nextssl-col">Yes</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
            </tr>
            <tr>
              <td class="feature-col">Threshold / MPC primitives</td>
              <td class="nextssl-col">52 algorithms</td>
              <td class="dis">None</td>
              <td class="dis">None</td>
              <td class="dis">None</td>
              <td class="dis">None</td>
              <td class="dis">None</td>
            </tr>
            <tr>
              <td class="feature-col">WASM compilation target</td>
              <td class="nextssl-col">Yes</td>
              <td class="dis">Limited</td>
              <td class="dis">No</td>
              <td>Yes</td>
              <td>Yes</td>
              <td class="dis">Partial</td>
            </tr>
            <tr>
              <td class="feature-col">Lightweight crypto (NIST LWC)</td>
              <td class="nextssl-col">Full Ascon family</td>
              <td class="dis">None</td>
              <td class="dis">None</td>
              <td class="dis">None</td>
              <td class="dis">Partial</td>
              <td class="dis">None</td>
            </tr>
            <tr>
              <td class="feature-col">Hardware instruction auto-select</td>
              <td class="nextssl-col">Runtime detection</td>
              <td class="dis">Compile-time flags</td>
              <td>Runtime</td>
              <td>Yes</td>
              <td class="dis">Partial</td>
              <td class="dis">Compile-time</td>
            </tr>
            <tr>
              <td class="feature-col">FIPS 140-3 path</td>
              <td class="nextssl-col">Planned</td>
              <td>Yes (module)</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td>Yes</td>
              <td>Yes</td>
            </tr>
            <tr>
              <td class="feature-col">License</td>
              <td class="nextssl-col">Apache-2.0</td>
              <td>Apache-2.0</td>
              <td>BSD / ISC mix</td>
              <td>ISC</td>
              <td class="dis">GPL / Commercial</td>
              <td>Apache-2.0</td>
            </tr>
            <tr>
              <td class="feature-col">Noise Protocol framework</td>
              <td class="nextssl-col">13 patterns</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
            </tr>
            <tr>
              <td class="feature-col">Embedded / IoT optimized</td>
              <td class="nextssl-col">Yes (LWC + WASM)</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">Partial</td>
              <td>Yes</td>
              <td>Yes (primary focus)</td>
            </tr>
            <tr>
              <td class="feature-col">Algo Modularity (remove, add, build)</td>
              <td class="nextssl-col">Yes (modular archive)</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
              <td class="dis">No</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="reveal" style="margin-top:20px;font-size:12px;color:var(--slate);text-align:right">
        Comparison reflects publicly documented feature sets. FIPS 140-3 certification status varies by build and module
        version.
      </div>
    </div>
  </section>
  <!-- CTA -->
  <section id="cta">
    <div class="container">
      <div class="reveal">
        <div style="max-width:2px;height:48px;background:var(--border);margin:0 auto 48px;position:relative">
          <div
            style="position:absolute;top:0;left:50%;transform:translateX(-50%);width:2px;height:100%;background:linear-gradient(180deg,transparent,var(--green))">
          </div>
        </div>
        <div class="cta-quote">
          <em>Cryptography is the last line of defense.</em><br>
          We built NextSSL because that line deserves a solid foundation: one that handles today's TLS stack and
          tomorrow's post-quantum migration without forcing your team to start over.
        </div>
        <div style="height:40px"></div>
        <a href="https://github.com/QudsLab/NextSSL" target="_blank" class="cta-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path
              d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
          </svg>
          Star NextSSL on GitHub
        </a>
        <div class="cta-meta">
          Built by <strong>QudsLab</strong>. Open source forever. Apache-2.0.
        </div>
        <div class="org-logo">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 2L2 7l10 5 10-5-10-5z" />
            <path d="M2 17l10 5 10-5" />
            <path d="M2 12l10 5 10-5" />
          </svg>
        </div>
      </div>
    </div>
  </section>
  <!-- Footer -->
  <footer>
    <div class="container">
      <div class="footer-top">
        <div class="footer-brand-col">
          <div class="footer-brand-logo">
            <div class="logo-mark">
              <svg id="Layer_2" data-name="Layer 2" xmlns="http://www.w3.org/2000/svg" viewBox="235 0 1360 1623">
                <defs>
                  <style>
                    .cls-1 {
                      fill: #ff8800;
                      stroke: #4d2500;
                      stroke-miterlimit: 10;
                      stroke-width: 8px;
                    }
                    .cls-1 {
                      opacity: .94;
                    }
                  </style>
                </defs>
                <g id="Layer_1-2" data-name="Layer 1">
                  <path class="cls-1"
                    d="M912.81,5.23c-220.66,130.69-440.61,260.95-661.23,391.62-2.67,1.58-4.31,4.45-4.31,7.55v797.96c0,3.1,1.63,5.97,4.3,7.55,220.66,131.02,440.96,261.82,661.24,392.61,2.76,1.64,6.2,1.64,8.97,0,221.95-131.7,441.77-262.15,660.33-391.84,2.66-1.58,4.29-4.45,4.29-7.54V403.88c0-3.1-1.64-5.97-4.31-7.55C1361.79,265.85,1142.34,135.87,921.76,5.23c-2.76-1.63-6.19-1.63-8.95,0ZM1479.02,678.62c-24.89,14.57-49.96,29.24-77.82,45.54-5.85,3.42-13.21-.79-13.21-7.57v-194.21c0-3.1-1.63-5.97-4.29-7.55-154.56-91.99-307.32-182.9-461.79-274.83-2.77-1.65-6.22-1.65-8.99,0-153.79,91.52-307,182.69-459.93,273.69-2.66,1.58-4.28,4.44-4.28,7.54v327.28c0,3.09,1.62,5.95,4.27,7.53l463.67,277.15.75.44c183.96-109.42,367.92-218.84,551.88-328.26,5.85-3.48,13.26.74,13.26,7.54v331.65c0,3.1-1.63,5.96-4.29,7.54-184.08,109.21-369.61,219.29-556.37,330.09-2.76,1.64-6.2,1.64-8.96,0-186.48-110.58-372.56-220.91-558.33-331.07-2.66-1.58-4.3-4.45-4.3-7.54,0-16.38,0-68.9,0-95.27,0-6.8,7.41-11.01,13.27-7.54,184.6,109.56,366.26,217.38,549.36,326.05,2.76,1.64,6.21,1.64,8.97,0,154.01-91.55,306.32-182.08,459.32-273.03,2.66-1.58,4.29-4.45,4.29-7.55v-100.14c0-6.81-7.42-11.02-13.27-7.54-152.06,90.47-300.65,178.87-450.43,267.98-2.77,1.65-6.21,1.65-8.98,0-186.48-110.88-372.43-221.45-558.38-332.02-2.66-1.58-4.29-4.45-4.29-7.54v-443.36c0-3.1,1.63-5.96,4.3-7.54,185.01-109.6,371.08-219.84,558.2-330.69,2.76-1.63,6.19-1.63,8.95,0,186.71,110.56,372.29,220.45,557.46,330.11,2.67,1.58,4.3,4.45,4.3,7.55v207.99c0,3.12-1.65,6-4.34,7.57ZM1184.04,839.22v-202.04c0-3.09-1.62-5.95-4.27-7.53-85.69-51.26-171.23-102.43-257.9-154.28-2.77-1.66-6.24-1.66-9.02,0-86.92,51.86-173.01,103.21-258.38,154.14-2.65,1.58-4.27,4.44-4.27,7.52v202.2c0,6.81-7.41,11.02-13.26,7.54l-82.15-48.9c-2.66-1.58-4.29-4.45-4.29-7.54v-209.71c0-3.1,1.64-5.97,4.3-7.55,120.21-71.51,238.63-141.95,358.18-213.06,2.77-1.65,6.22-1.65,8.99,0,119.05,70.93,237.39,141.43,357.33,212.89,2.66,1.58,4.29,4.45,4.29,7.55v209.84c0,3.09-1.63,5.95-4.28,7.53l-82,48.92c-5.85,3.49-13.27-.72-13.27-7.53ZM753.32,910.63v-214.08c0-3.08,1.62-5.95,4.27-7.53,51.89-31.17,103.13-61.95,155.05-93.13,2.78-1.67,6.27-1.67,9.06,0,51.59,30.98,102.31,61.43,153.79,92.35,2.64,1.59,4.27,4.45,4.27,7.53v215.68c0,3.08-1.62,5.94-4.26,7.52-51.98,31.17-104.17,62.47-158.05,94.77h-.01c-53.39-31.93-106.61-63.75-159.84-95.58-2.65-1.58-4.27-4.44-4.27-7.53Z" />
                </g>
              </svg>
            </div>
            NextSSL
          </div>
          <p class="footer-mission">The universal cryptographic surface. Built for researchers, builders, and engineers
            who can't afford to get it wrong. Open source forever.</p>
          <div class="footer-badge-row">
            <span class="footer-badge">Apache-2.0</span>
            <span class="footer-badge">C99 Core</span>
            <span class="footer-badge">776 Algorithms</span>
            <span class="footer-badge">22 Categories</span>
          </div>
        </div>
        <div>
          <div class="footer-col-title">Library</div>
          <div class="footer-col-links">
            <a href="https://github.com/QudsLab/NextSSL" target="_blank">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path
                  d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
              </svg>
              GitHub Repository
            </a>
            <a href="https://github.com/QudsLab/NextSSL/wiki" target="_blank">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
              </svg>
              Documentation
            </a>
            <a href="https://github.com/QudsLab/NextSSL/blob/main/CHANGELOG.md" target="_blank">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10" />
                <polyline points="12 6 12 12 16 14" />
              </svg>
              Changelog
            </a>
            <a href="https://github.com/QudsLab/NextSSL/blob/main/LICENSE" target="_blank">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Apache-2.0 License
            </a>
          </div>
        </div>
        <div>
          <div class="footer-col-title">Learn</div>
          <div class="footer-col-links">
            <a href="#algorithms">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.35-4.35" />
              </svg>
              Algorithm Browser
            </a>
            <a href="#usecases">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="2" y="7" width="20" height="14" rx="2" />
                <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
              </svg>
              Use Cases
            </a>
            <a href="#timeline">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="12" y1="2" x2="12" y2="22" />
                <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
              </svg>
              PQC Roadmap
            </a>
            <a href="https://github.com/QudsLab/NextSSL/blob/main/SECURITY.md" target="_blank">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Security Policy
            </a>
          </div>
        </div>
        <div>
          <div class="footer-col-title">Community</div>
          <div class="footer-col-links">
            <a href="https://github.com/QudsLab/NextSSL/blob/main/CONTRIBUTING.md" target="_blank">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                <path d="M16 3.13a4 4 0 0 1 0 7.75" />
              </svg>
              Contributing Guide
            </a>
            <a href="https://github.com/QudsLab/NextSSL/blob/main/CODE_OF_CONDUCT.md" target="_blank">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path
                  d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z" />
              </svg>
              Code of Conduct
            </a>
            <a href="https://github.com/QudsLab/NextSSL/issues" target="_blank">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              Issues &amp; Bugs
            </a>
            <a href="https://github.com/QudsLab/NextSSL/discussions" target="_blank">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
              </svg>
              Discussions
            </a>
          </div>
        </div>
      </div>
      <hr class="footer-divider">
      <div class="footer-bottom">
        <div class="footer-copy-text">
          &copy; 2025&ndash;2026 <a href="https://github.com/QudsLab" target="_blank">QudsLab</a>. Open source under <a
            href="https://github.com/QudsLab/NextSSL/blob/main/LICENSE" target="_blank">Apache-2.0</a>.
        </div>
        <div class="footer-micro-stats">
          <span>776</span> algorithms
          <span style="color:var(--border)">·</span>
          <span>22+</span> categories
          <span style="color:var(--border)">·</span>
          <span>29</span> binary targets
        </div>
      </div>
    </div>
  </footer>
</body>
</html>