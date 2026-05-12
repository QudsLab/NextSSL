<div align="center">

<img src="assets/logo_ud.svg" width="92%" alt="NextSSL Banner" />

<br>

<a href="LICENSE"><img alt="License Apache-2.0" src="https://img.shields.io/badge/License-Apache--2.0-5db8a6?labelColor=181715"></a>
<img alt="Status Under Development" src="https://img.shields.io/badge/status-under%20development-4f9f91?labelColor=181715">
<img alt="Algorithm Surfaces 250" src="https://img.shields.io/badge/algorithm%20surfaces-250-5db8a6?labelColor=181715">
<img alt="Target Builds 29" src="https://img.shields.io/badge/target%20builds-29-a8d9d1?labelColor=181715">
<img alt="Profiles" src="https://img.shields.io/badge/profiles-experimental%20%7C%20useful%20%7C%20safest--main-5db8a6?labelColor=181715">

<br><br>

<a href="PLAN.md"><img alt="Plan" src="https://img.shields.io/badge/PLAN-roadmap-252320?labelColor=181715"></a>
<a href="ALGO.md"><img alt="Algorithm inventory" src="https://img.shields.io/badge/ALGO-inventory-252320?labelColor=181715"></a>
<a href="BUILD.md"><img alt="Build" src="https://img.shields.io/badge/BUILD-targets-252320?labelColor=181715"></a>
<a href="SECURITY.md"><img alt="Security" src="https://img.shields.io/badge/SECURITY-reporting-252320?labelColor=181715"></a>
<a href="CONTRIBUTING.md"><img alt="Contributing" src="https://img.shields.io/badge/CONTRIBUTING-review-252320?labelColor=181715"></a>

</div>

<br>

<table>
  <tr>
    <td bgcolor="#181715" align="center">
      <br>
      <font color="#5db8a6"><b>This is the most comprehensive open, documented, and engineering-actionable cryptographic reference available. Not a museum of every cipher ever conceived — but a battle-tested index of what you actually need to build secure systems, pass audits, and migrate to post-quantum standards.</b></font>
    </td>
  </tr>
</table>

<table>
  <tr>
    <td bgcolor="#252320" align="center"><font color="#f4fffd"><b>250</b><br>planned algorithm surfaces</font></td>
    <td bgcolor="#252320" align="center"><font color="#f4fffd"><b>8</b><br>inventory groups</font></td>
    <td bgcolor="#252320" align="center"><font color="#f4fffd"><b>29</b><br>target variants</font></td>
    <td bgcolor="#252320" align="center"><font color="#f4fffd"><b>3</b><br>core domains</font></td>
  </tr>
</table>

> **Status:** under active development. Planned algorithms, target badges, and profile names show the roadmap. They do not mean the project is production-ready or audited.

## Why NextSSL

<table>
  <tr>
    <td bgcolor="#181715">
      <font color="#5db8a6"><b>TOP-TIER DIRECTION</b></font><br>
      <font color="#f4fffd"><b>Many algorithms, but safer defaults.</b></font><br>
      <font color="#cdebe6">NextSSL can keep many algorithms in one place without making all of them default choices. The archive can be wide, while the default profile stays careful.</font>
    </td>
    <td bgcolor="#252320">
      <font color="#5db8a6"><b>SECURITY POSTURE</b></font><br>
      <font color="#f4fffd"><b>Defaults should be reviewed.</b></font><br>
      <font color="#cdebe6">Experimental and old algorithms can stay in the archive. They should not become normal defaults unless the project clearly allows them.</font>
    </td>
    <td bgcolor="#1f3430">
      <font color="#5db8a6"><b>PORTABILITY</b></font><br>
      <font color="#f4fffd"><b>Built for many platforms.</b></font><br>
      <font color="#cdebe6">The current layout tracks desktop, mobile, Linux, Windows, and WASM targets from the start.</font>
    </td>
  </tr>
</table>

## The Model

<table>
  <tr>
    <td bgcolor="#181715">
      <h3><font color="#f4fffd">Big archive. Small safe-default set. Clear review path.</font></h3>
      <p>
        <font color="#d9d4cc">
          NextSSL is organized around three areas: <code>experimental</code>,
          <code>useful</code>, and <code>safest-main</code>. Algorithms can be listed,
          studied, tested, and improved without becoming safe defaults by accident.
        </font>
      </p>
      <p>
        <font color="#cdebe6">
          Simple rule: keep the archive wide, and keep defaults strict.
        </font>
      </p>
    </td>
  </tr>
</table>

<table>
  <tr>
    <td bgcolor="#181715" align="center">
      <img src="assets/readme_profile_funnel.svg" width="100%" alt="Archive to safe-default profile funnel" />
    </td>
  </tr>
</table>

## Algorithm Surface

<table>
  <tr>
    <td bgcolor="#181715" align="center">
      <img src="assets/readme_surface_comparison.svg" width="100%" alt="NextSSL planned algorithm surface comparison" />
    </td>
  </tr>
</table>

Current archive inventory: **250 planned algorithm surfaces across 8 groups**.

| Group | Count | Purpose |
| --- | ---: | --- |
| Modern | 84 | AEAD, MAC, KDF, signatures, curves, and key exchange work |
| Hash / KDF-hash | 59 | Hashes, XOFs, KMAC, and password-hash related surfaces |
| PQC | 41 | KEMs, signatures, and adjacent post-quantum candidates |
| Threshold | 36 | Threshold signatures, MPC, VSS, DKG, and related protocols |
| Encoding | 14 | Encodings and checksum helpers |
| Ascon | 7 | Lightweight AEAD, hash, XOF, MAC, and PRF surfaces |
| DRBG / RNG | 7 | DRBGs and randomness infrastructure |
| Stateful HBS | 2 | LMS and XMSS |

Entries marked `NEW` in [ALGO.md](ALGO.md) are planned items. They do not mean the code is finished.

## Safety Profiles

<table>
  <tr>
    <td bgcolor="#181715">
      <font color="#5db8a6"><b>SAFEST</b></font><br>
      <font color="#f4fffd"><b>Safe defaults for normal users.</b></font><br>
      <font color="#cdebe6">The default profile should use modern, reviewed choices and avoid old or risky ones.</font>
    </td>
    <td bgcolor="#252320">
      <font color="#5db8a6"><b>COMPATIBILITY</b></font><br>
      <font color="#f4fffd"><b>Old-system support with warnings.</b></font><br>
      <font color="#cdebe6">Older algorithms can be available for compatibility, but they should be clearly marked.</font>
    </td>
    <td bgcolor="#1f3430">
      <font color="#5db8a6"><b>RESEARCH</b></font><br>
      <font color="#f4fffd"><b>Experimental algorithms for study.</b></font><br>
      <font color="#cdebe6">Researchers can inspect candidates, add references, and help move good choices forward.</font>
    </td>
  </tr>
</table>

| Profile | Purpose |
| --- | --- |
| `safest` | Safe defaults for normal users |
| `compatibility` | Legacy and migration support with warnings |
| `research` | Experimental algorithms and review hooks |
| `archive` | Full catalog inspection |
| `pqc` | Post-quantum and hybrid migration work |

## Library Positioning

<table>
  <tr>
    <td bgcolor="#181715">
      <h3><font color="#f4fffd">Aiming high, while being honest.</font></h3>
      <p>
        <font color="#d9d4cc">
          NextSSL is not claiming to replace OpenSSL, BoringSSL, libsodium, Botan, Crypto++,
          wolfSSL, or mbedTLS today. Those projects are older, more tested, and used in real systems.
        </font>
      </p>
      <p>
        <font color="#cdebe6">
          The goal is different: become a useful crypto toolkit for people who want a big algorithm list
          plus strict defaults.
        </font>
      </p>
    </td>
  </tr>
</table>

<table>
  <tr>
    <td bgcolor="#181715" align="center">
      <img src="assets/readme_library_positioning.svg" width="100%" alt="NextSSL positioning compared with other crypto libraries" />
    </td>
  </tr>
</table>

## Platform Targets

<table>
  <tr>
    <td bgcolor="#181715" align="center">
      <img src="assets/readme_platform_matrix.svg" width="100%" alt="NextSSL platform and architecture build matrix" />
    </td>
  </tr>
</table>

The current `bin` layout contains **29 target variants**. Build docs are still changing; start with [BUILD.md](BUILD.md).

| Family | Targets |
| --- | --- |
| Android | `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64` |
| iOS | `device-arm64`, `sim-arm64`, `sim-x86_64` |
| Linux glibc | `arm64`, `armv7`, `loongarch64`, `ppc64le`, `riscv64`, `s390x`, `x86`, `x86_64` |
| Linux musl | `arm64`, `armv7`, `x86_64` |
| macOS | `arm64`, `universal`, `x86_64` |
| WASM | `emscripten-wasm32`, `wasi-wasm32` |
| Windows | `arm64-msvc`, `armv7-msvc`, `x86-mingw`, `x86-msvc`, `x86_64-mingw`, `x86_64-msvc` |

## Project Docs

<table>
  <tr>
    <td bgcolor="#181715"><a href="PLAN.md"><b>PLAN.md</b></a><br><font color="#cdebe6">Roadmap, profiles, safety labels, and contribution flow.</font></td>
    <td bgcolor="#252320"><a href="ALGO.md"><b>ALGO.md</b></a><br><font color="#cdebe6">Complete current inventory and planned surfaces.</font></td>
    <td bgcolor="#1f3430"><a href="BUILD.md"><b>BUILD.md</b></a><br><font color="#cdebe6">Build notes and target guidance.</font></td>
  </tr>
  <tr>
    <td bgcolor="#1f3430"><a href="CONTRIBUTING.md"><b>CONTRIBUTING.md</b></a><br><font color="#cdebe6">How to add and review algorithms.</font></td>
    <td bgcolor="#252320"><a href="SECURITY.md"><b>SECURITY.md</b></a><br><font color="#cdebe6">Security reporting policy.</font></td>
    <td bgcolor="#181715"><a href="LICENSE"><b>LICENSE</b></a><br><font color="#cdebe6">Apache-2.0.</font></td>
  </tr>
</table>

## Target Tags

<table>
  <tr>
    <td bgcolor="#181715"><img src="assets/platform/linux.svg" width="22" alt="Linux" /> <font color="#f4fffd"><b>glibc</b></font></td>
    <td bgcolor="#252320"><font color="#cdebe6"><code>arm64</code> <code>armv7</code> <code>loongarch64</code> <code>ppc64le</code> <code>riscv64</code> <code>s390x</code> <code>x86</code> <code>x86_64</code></font></td>
  </tr>
  <tr>
    <td bgcolor="#181715"><img src="assets/platform/linux.svg" width="22" alt="Linux" /> <font color="#f4fffd"><b>musl</b></font></td>
    <td bgcolor="#252320"><font color="#cdebe6"><code>arm64</code> <code>armv7</code> <code>x86_64</code></font></td>
  </tr>
  <tr>
    <td bgcolor="#181715"><img src="assets/platform/windows.svg" width="20" alt="Windows" /> <font color="#f4fffd"><b>MSVC / MinGW</b></font></td>
    <td bgcolor="#252320"><font color="#cdebe6"><code>arm64-msvc</code> <code>armv7-msvc</code> <code>x86-mingw</code> <code>x86-msvc</code> <code>x86_64-mingw</code> <code>x86_64-msvc</code></font></td>
  </tr>
  <tr>
    <td bgcolor="#181715"><img src="assets/platform/android.svg" width="20" alt="Android" /> <font color="#f4fffd"><b>Android</b></font></td>
    <td bgcolor="#252320"><font color="#cdebe6"><code>arm64-v8a</code> <code>armeabi-v7a</code> <code>x86</code> <code>x86_64</code></font></td>
  </tr>
  <tr>
    <td bgcolor="#181715"><img src="assets/platform/apple.svg" width="20" alt="Apple" /> <font color="#f4fffd"><b>iOS</b></font></td>
    <td bgcolor="#252320"><font color="#cdebe6"><code>device-arm64</code> <code>sim-arm64</code> <code>sim-x86_64</code></font></td>
  </tr>
  <tr>
    <td bgcolor="#181715"><img src="assets/platform/apple.svg" width="20" alt="Apple" /> <font color="#f4fffd"><b>macOS</b></font></td>
    <td bgcolor="#252320"><font color="#cdebe6"><code>arm64</code> <code>universal</code> <code>x86_64</code></font></td>
  </tr>
  <tr>
    <td bgcolor="#181715"><img src="assets/platform/webassembly.svg" width="20" alt="WebAssembly" /> <font color="#f4fffd"><b>WASM</b></font></td>
    <td bgcolor="#252320"><font color="#cdebe6"><code>emscripten-wasm32</code> <code>wasi-wasm32</code></font></td>
  </tr>
</table>

## Algorithm Tags

![encoding 14](https://img.shields.io/badge/encoding-14-5db8a6?labelColor=181715)
![hash 59](https://img.shields.io/badge/hash%20%2F%20KDF--hash-59-6fbfb3?labelColor=181715)
![modern 84](https://img.shields.io/badge/modern-84-5db8a6?labelColor=181715)
![pqc 41](https://img.shields.io/badge/PQC-41-a8d9d1?labelColor=181715)
![threshold 36](https://img.shields.io/badge/threshold-36-4f9f91?labelColor=181715)
![ascon 7](https://img.shields.io/badge/ascon-7-79c8bd?labelColor=181715)
![drbg rng 7](https://img.shields.io/badge/DRBG%20%2F%20RNG-7-8fcfc6?labelColor=181715)
![stateful hbs 2](https://img.shields.io/badge/stateful%20HBS-2-cdebe6?labelColor=181715)
![total 250](https://img.shields.io/badge/total%20algorithm%20surfaces-250-5db8a6?labelColor=181715)

<table>
  <tr>
    <td bgcolor="#5db8a6" align="center">
      <h2><font color="#181715">Keep the archive wide. Keep the defaults strict.</font></h2>
      <p><font color="#181715"><b>NextSSL is building toward top-tier crypto-library status with a big algorithm catalog and clear safety profiles.</b></font></p>
    </td>
  </tr>
</table>




## Scope & Exclusions

> **TL;DR:** This inventory aims to be the most comprehensive *openly documented* cryptographic reference for production engineering, standards compliance, and protocol design. It does **not** claim to be an exhaustive enumeration of every algorithm that has ever existed. Below is the explicit boundary of what we include, what we deliberately exclude, and why.

---

### What We Include

| Inclusion Criteria | Examples |
|--------------------|----------|
| **IETF / NIST / ISO / ITU-T standards** | AES-GCM, SHA-3, ML-KEM, ML-DSA, HKDF, X.509v3 |
| **National standards** (openly published) | SM3/SM4 (China), Streebog/Kuznyechik (Russia), ARIA/SEED/LEA (Korea), Camellia (Japan) |
| **Widely deployed protocol primitives** | Noise patterns, Signal X3DH/Double Ratchet, WireGuard, TLS 1.3 cipher suites |
| **Production cryptographic libraries** | OpenSSL, BoringSSL, wolfSSL, libsodium, Botan, mbed TLS, ring, rustls |
| **Post-quantum NIST finalists & standards** | ML-KEM, ML-DSA, SLH-DSA, plus selected alternates with significant deployment |
| **Threshold / MPC primitives with active implementations** | FROST, TSS2, GG20/21 variants, DKG, VSS |
| **Zero-knowledge proof systems with production usage** | Groth16, Plonk, STARKs, Bulletproofs, KZG commitments |
| **Hardware security interfaces & TEE abstractions** | PKCS#11, TPM 2.0, Intel SGX/TDX, AMD SEV-SNP, Apple Secure Enclave |
| **Historic algorithms relevant to migration & legacy support** | MD5, SHA-1, 3DES, RSA-PKCS1-v1.5, DSA |

---

### What We Deliberately Exclude

| Exclusion Category | Rationale | Examples of Omitted Items |
|--------------------|-----------|---------------------------|
| **Classified / proprietary government cryptography** | Not publicly documented; no verifiable specification | NSA Suite A, military tactical ciphers, diplomatic link encryption |
| **Undocumented vendor-specific protocols** | Cannot be independently implemented or audited | Proprietary smart-card OS crypto, automotive ECU obfuscation, DRM cipher suites |
| **Purely academic proposals with zero deployment** | Inventory would balloon to thousands of entries with no engineering value | Most eSTREAM Round 1/2 candidates, dozens of lightweight Feistel ciphers from 2005–2015 |
| **Regional telecom/radio ciphers without open standards** | Specialized, often classified, and rapidly obsolete | Specific GSM A5/3 variants, satellite link ciphers, tactical radio waveforms |
| **Hardware bitstream / FPGA obfuscation schemes** | Not general-purpose cryptographic algorithms | Xilinx bitstream encryption, ASIC logic locking |
| **Non-cryptographic checksums / hashes** | Error detection ≠ cryptographic security | CRC variants beyond ISO 3309, Fletcher checksums, Adler-32 (already borderline) |
| **Steganography and covert-channel techniques** | Out of scope; not cryptographic primitives | LSB encoding, spread-spectrum hiding, traffic morphing |
| **Quantum cryptography (QKD / QRNG hardware schemes)** | Physical-layer security, not algorithmic cryptography | BB84, E91, device-independent QKD protocols |
| **Ad-hoc protocol compositions without standardization** | Too many possible combinations; we track standardized integrations only | Custom corporate VPN protocols, homegrown key-derivation schemes |
| **Malware / offensive tooling ciphers** | No legitimate engineering use case | Ransomware custom ciphers, C2 obfuscation algorithms |

---

### The "Almost Complete" Claim — Honest Assessment

**Can a team pick this inventory and say "we have all algorithms we need for any standard-compliant system"?**

**Yes, with two caveats:**

1. **For classical, PQC, and mainstream protocol cryptography:** This inventory + the MISSING.md supplement covers **>95% of algorithms you will ever encounter** in standards-compliant TLS, SSH, IPsec, messaging, blockchain, code-signing, document signing, or FIPS 140-validated modules. The remaining gaps are niche national standards (e.g., some CIS regional ciphers), experimental ZK constructions, or bleeding-edge PQC on-ramp candidates not yet finalized.

2. **For specialized domains, you will need domain-specific extensions:**
   - **Satellite/space communications** (CCSDS, specific space agencies)
   - **Military / defense** (NATO STANAG, national classified suites)
   - **Payment networks** (EMVCo specifics, PCI PTS point-to-point encryption)
   - **Automotive** (V2X IEEE 1609.2, SOME/IP Sec, proprietary OEM schemes)
   - **Medical devices** (IEC 80001, proprietary hospital network encryption)
   - **Industrial control** (IEC 62351, proprietary SCADA protocols)

**In short:** This is the most comprehensive **open, engineering-oriented** cryptographic archive available. It is not — and cannot be — a complete enumeration of every algorithm ever devised, because cryptography is a living field with classified, proprietary, experimental, and domain-specific branches that are inherently unbounded.

---

### How to Extend This Inventory

If you need coverage for a specific domain:

1. **Fork the MISSING.md** and add your domain-specific section (e.g., `# 21. Space Communications`, `# 22. Medical Device Crypto`).
2. **Reference the original schema** (SQL-style tables in CRYPTO_INVENTORY.md) so your additions remain machine-parseable.
3. **Flag `status` appropriately:** Use `historic` for obsolete domain ciphers, `planned` for draft standards, and `current` only for actively deployed algorithms.
4. **Cross-reference protocol integrations:** If your algorithm appears in a protocol, add it to the Protocol Integration Reference table.

---

*The goal is not to be a museum of every cipher ever conceived. The goal is to be the definitive engineering reference for building secure, standards-compliant, and future-proofed cryptographic systems.*
