# NextSSL Plan

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-yellow.svg)](LICENSE)
![Status: Under Development](https://img.shields.io/badge/status-under%20development-orange)
![Algorithm Surfaces: 249](https://img.shields.io/badge/algorithm%20surfaces-249-blue)
![Profile Model](https://img.shields.io/badge/profile%20model-experimental%20%7C%20useful%20%7C%20safest--main-6d5796)

NextSSL is being shaped as a crypto archive with safe defaults. The archive can grow wide, but users should land on a small, reliable, reviewed path unless they explicitly choose otherwise.

See [ALGO.md](ALGO.md) for the current algorithm inventory.

## Core Idea

NextSSL should support three different audiences without mixing their safety expectations:

1. Researchers need room to add experimental algorithms, compare designs, and preserve old or unusual primitives.
2. Builders need useful algorithms for real ecosystems, compatibility, wallets, protocols, and migrations.
3. Normal users need the safest main defaults without learning every crypto foot-gun first.

The library should feel like an archive from the inside and a safe toolkit from the outside.

## Profile Domains

Every algorithm surface should belong to one or more profile domains.

| Domain | Purpose | Default exposure |
| --- | --- | --- |
| `experimental` | Research, drafts, prototypes, candidates, unusual schemes | Hidden unless explicitly enabled |
| `useful` | Practical algorithms with real ecosystem value, including legacy and compatibility surfaces | Available with policy labels |
| `safest-main` | Conservative, reviewed defaults for normal users | Used by default |

## Profile Customization

Profiles should be objects, not hard-coded magic. A user should be able to inspect defaults, clone a profile, change selected defaults, and still keep policy checks.

```js
const NP = NextSSL.profile.safest();

NP.default.hash = NextSSL.root.hash.sha256;
NP.default.passwordKdf = NextSSL.root.hash.argon2id;
NP.default.aead = NextSSL.root.modern["xchacha20-poly1305"];
NP.default.signature = NextSSL.root.modern.ed25519;
NP.default.kex = NextSSL.root.modern.x25519;
```

Expert customization should be possible:

```js
const NP = NextSSL.profile.safest();

// Explicit override. This should trigger a warning or policy event.
NP.default.hash = NextSSL.root.hash.md5;
```

The design goal is not to forbid experts. The goal is to make dangerous choices visible, reviewable, and never accidental.

## Default Profiles

| Profile | Intended user | Behavior |
| --- | --- | --- |
| `NextSSL.profile.safest()` | Normal production users | Conservative defaults, strict warnings, no weak algorithms by default |
| `NextSSL.profile.compatibility()` | Apps migrating from older systems | Allows selected legacy algorithms with clear labels |
| `NextSSL.profile.research()` | Researchers and reviewers | Exposes experimental surfaces and test hooks |
| `NextSSL.profile.archive()` | Catalog and comparison users | Makes the full archive inspectable, not production-default |
| `NextSSL.profile.pqc()` | Post-quantum migration work | Prefers PQC and hybrid-ready surfaces |

## Suggested Safest Defaults

These are planning targets, not final guarantees.

| Category | Default direction |
| --- | --- |
| Hash | `sha256`, `sha512`, or `blake3` depending on mode |
| Password KDF | `argon2id` |
| AEAD | `xchacha20-poly1305` or `aes-gcm` |
| MAC | `hmac-sha256`, `aes-cmac`, or `kmac` depending on primitive family |
| Key exchange | `x25519`, `hpke`, or hybrid PQC profile |
| Signature | `ed25519`, `ecdsa`, or `rsa-pss` where needed |
| RNG | `csprng-system` plus DRBG policy where required |

## Algorithm Lifecycle

Algorithms should move through lifecycle states by evidence, not hype.

```text
proposed -> experimental -> useful -> safest-main
                    |             |
                    v             v
              deprecated     compatibility-only
                    |
                    v
                 removed
```

Promotion should require:

- Clear algorithm metadata.
- Test vectors.
- Known security notes.
- Side-channel review notes where relevant.
- Interoperability tests for protocol algorithms.
- Maintainer approval through an issue or review thread.

## Safety Labels

Each algorithm should carry labels that profiles can understand.

| Label | Meaning |
| --- | --- |
| `recommended` | Safe candidate for default use |
| `legacy` | Kept for compatibility, not new designs |
| `deprecated` | Should not be used unless migration requires it |
| `dangerous-if-misused` | Requires strict API guardrails |
| `constant-time-required` | Implementation must be side-channel reviewed |
| `research` | Not production-ready |
| `pqc` | Post-quantum surface |
| `hybrid-ready` | Can be paired with classical or PQC primitives |
| `archive-only` | Cataloged for reference, not intended for normal use |

## Archive Shape

<svg width="760" height="220" viewBox="0 0 760 220" role="img" aria-label="NextSSL archive profile funnel">
  <rect x="0" y="0" width="760" height="220" rx="18" fill="#0f172a"/>
  <text x="380" y="34" text-anchor="middle" fill="#e5e7eb" font-size="20" font-family="Arial, sans-serif">Archive width with safe-default funnel</text>
  <rect x="70" y="62" width="620" height="42" rx="12" fill="#334155"/>
  <text x="380" y="89" text-anchor="middle" fill="#f8fafc" font-size="15" font-family="Arial, sans-serif">Full archive: experimental + useful + safest-main</text>
  <rect x="150" y="116" width="460" height="36" rx="10" fill="#2563eb"/>
  <text x="380" y="140" text-anchor="middle" fill="#eff6ff" font-size="14" font-family="Arial, sans-serif">Useful profile: practical, labeled, opt-in compatibility</text>
  <rect x="260" y="164" width="240" height="34" rx="10" fill="#16a34a"/>
  <text x="380" y="186" text-anchor="middle" fill="#ecfdf5" font-size="14" font-family="Arial, sans-serif">Safest-main defaults</text>
</svg>

## Algorithm Surface Comparison

The current inventory tracks 249 algorithm surfaces across 8 groups. This is an archive count, not an implementation guarantee.

<svg width="760" height="310" viewBox="0 0 760 310" role="img" aria-label="Algorithm surface comparison chart">
  <rect width="760" height="310" rx="18" fill="#111827"/>
  <text x="32" y="38" fill="#f9fafb" font-size="20" font-family="Arial, sans-serif">Planned algorithm surface by group</text>
  <text x="32" y="62" fill="#9ca3af" font-size="12" font-family="Arial, sans-serif">Counts come from ALGO.md and include planned NEW surfaces.</text>
  <g font-family="Arial, sans-serif" font-size="13">
    <text x="32" y="99" fill="#d1d5db">Modern</text>
    <rect x="160" y="84" width="498" height="18" rx="4" fill="#38bdf8"/>
    <text x="670" y="99" fill="#f9fafb">83</text>
    <text x="32" y="129" fill="#d1d5db">Hash / KDF-hash</text>
    <rect x="160" y="114" width="354" height="18" rx="4" fill="#a78bfa"/>
    <text x="526" y="129" fill="#f9fafb">59</text>
    <text x="32" y="159" fill="#d1d5db">PQC</text>
    <rect x="160" y="144" width="246" height="18" rx="4" fill="#fb7185"/>
    <text x="418" y="159" fill="#f9fafb">41</text>
    <text x="32" y="189" fill="#d1d5db">Threshold</text>
    <rect x="160" y="174" width="216" height="18" rx="4" fill="#f59e0b"/>
    <text x="388" y="189" fill="#f9fafb">36</text>
    <text x="32" y="219" fill="#d1d5db">Encoding</text>
    <rect x="160" y="204" width="84" height="18" rx="4" fill="#22c55e"/>
    <text x="256" y="219" fill="#f9fafb">14</text>
    <text x="32" y="249" fill="#d1d5db">Ascon</text>
    <rect x="160" y="234" width="42" height="18" rx="4" fill="#14b8a6"/>
    <text x="214" y="249" fill="#f9fafb">7</text>
    <text x="32" y="279" fill="#d1d5db">DRBG / RNG</text>
    <rect x="160" y="264" width="42" height="18" rx="4" fill="#eab308"/>
    <text x="214" y="279" fill="#f9fafb">7</text>
    <text x="520" y="279" fill="#d1d5db">Stateful HBS: 2</text>
  </g>
</svg>

## What Makes NextSSL Different

<svg width="760" height="260" viewBox="0 0 760 260" role="img" aria-label="NextSSL differentiator chart">
  <rect width="760" height="260" rx="18" fill="#f8fafc"/>
  <text x="380" y="36" text-anchor="middle" fill="#0f172a" font-size="21" font-family="Arial, sans-serif">Archive + policy, not just primitives</text>
  <g font-family="Arial, sans-serif">
    <rect x="42" y="72" width="200" height="132" rx="16" fill="#dbeafe"/>
    <text x="142" y="104" text-anchor="middle" fill="#1e3a8a" font-size="17">Crypto archive</text>
    <text x="142" y="132" text-anchor="middle" fill="#1e40af" font-size="12">Many algorithms can exist</text>
    <text x="142" y="152" text-anchor="middle" fill="#1e40af" font-size="12">without becoming defaults</text>
    <rect x="280" y="72" width="200" height="132" rx="16" fill="#dcfce7"/>
    <text x="380" y="104" text-anchor="middle" fill="#14532d" font-size="17">Safety profiles</text>
    <text x="380" y="132" text-anchor="middle" fill="#166534" font-size="12">Defaults are explicit</text>
    <text x="380" y="152" text-anchor="middle" fill="#166534" font-size="12">customizable and checked</text>
    <rect x="518" y="72" width="200" height="132" rx="16" fill="#ffedd5"/>
    <text x="618" y="104" text-anchor="middle" fill="#7c2d12" font-size="17">Research workflow</text>
    <text x="618" y="132" text-anchor="middle" fill="#9a3412" font-size="12">Issues, vectors, review</text>
    <text x="618" y="152" text-anchor="middle" fill="#9a3412" font-size="12">decide maturity</text>
  </g>
  <path d="M242 138 L280 138" stroke="#64748b" stroke-width="3"/>
  <path d="M480 138 L518 138" stroke="#64748b" stroke-width="3"/>
</svg>

## Contribution Flow

New algorithm contributions should follow a predictable path:

1. Open or reference an issue.
2. Add or update the inventory entry in [ALGO.md](ALGO.md).
3. Choose the initial domain: `experimental`, `useful`, or `safest-main`.
4. Add implementation notes, references, and test vectors.
5. Add profile metadata and safety labels.
6. Request review for promotion or default eligibility.

## Near-Term Roadmap

| Stage | Goal |
| --- | --- |
| 1 | Finalize archive inventory and naming rules |
| 2 | Define metadata schema for algorithms and profiles |
| 3 | Implement profile objects and default override policy |
| 4 | Add tests for profile selection and unsafe override warnings |
| 5 | Start promoting implemented algorithms into `useful` and `safest-main` |
| 6 | Build contributor workflow around issues, vectors, and review evidence |

## Rule of the Project

Breadth belongs in the archive. Trust belongs in the defaults.

NextSSL should make both possible without confusing one for the other.
