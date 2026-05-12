<?php require_once $_SERVER['DOCUMENT_ROOT'] . '/common/cache.php';?>
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
  <script src="<?php cprint('static/data.js'); ?>" defer></script>
  <script src="<?php cprint('static/site.js'); ?>" defer></script>
  <link rel="stylesheet"
    href="<?php cprint('static/style.css'); ?>">
</head>
<body>
<?php $nav_type = 'home'; require $_SERVER['DOCUMENT_ROOT'] . '/extension/header.php'; ?>
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
        <div class="timeline-entries" id="timeline-entries"></div>
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
      <div class="usecase-grid reveal" id="usecase-grid"></div>
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
      <div style="margin-top:48px" class="reveal" id="code-section-wrap"></div>
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
          <tbody id="compare-tbody"></tbody>
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
<?php require $_SERVER['DOCUMENT_ROOT'] . '/extension/footer.php'; ?>
</body>
</html>
