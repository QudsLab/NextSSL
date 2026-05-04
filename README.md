<div align="center">
   <img src="assets/logo_ud.svg" style="width: 90%;" alt="NextSSL Banner" />
</div>

# NextSSL

**Next Super Secure Layer** is an under-development crypto archive and safety-profile toolkit.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-yellow.svg)](LICENSE)
![Status: Under Development](https://img.shields.io/badge/status-under%20development-orange)
![Algorithm Surfaces: 249](https://img.shields.io/badge/algorithm%20surfaces-249-blue)
![Target Builds: 29](https://img.shields.io/badge/target%20builds-29-brightgreen)
![Profiles: experimental useful safest-main](https://img.shields.io/badge/profiles-experimental%20%7C%20useful%20%7C%20safest--main-6f42c1)

NextSSL is being designed as one repo with three clear domains: `experimental`, `useful`, and `safest-main`. Researchers can add and study algorithms, while normal users should get safe defaults through profiles.

> Status: under active development. Planned algorithm surfaces are not the same as implemented production code.

## The Shape

<div align="center">
   <img src="assets/readme_profile_funnel.svg" alt="Archive to safe-default profile funnel" />
</div>

NextSSL should be wide inside and careful outside:

- Broad archive: catalog algorithms, variants, research candidates, legacy systems, and ecosystem-specific primitives.
- Safe profiles: default to conservative choices unless the user explicitly customizes policy.
- Contributor workflow: use issues, references, test vectors, and review to promote algorithms between domains.

Full details live in [PLAN.md](PLAN.md). Current inventory lives in [ALGO.md](ALGO.md).

## Algorithm Surface

<div align="center">
   <img src="assets/readme_surface_comparison.svg" alt="NextSSL planned algorithm surface comparison" />
</div>

Current archive inventory: **249 planned algorithm surfaces across 8 groups**.

| Group | Count | Notes |
| --- | ---: | --- |
| Encoding | 14 | Encodings and checksum helpers |
| Hash / KDF-hash | 59 | Hashes, XOFs, KMAC, password hashes |
| Modern | 83 | AEAD, MAC, KDF, signatures, curves, KEX |
| PQC | 41 | KEMs, signatures, and adjacent PQC candidates |
| Threshold | 36 | Threshold signatures, MPC, VSS, DKG |
| Ascon | 7 | Lightweight AEAD, hash, XOF, MAC, PRF |
| DRBG / RNG | 7 | DRBGs and randomness infrastructure |
| Stateful HBS | 2 | LMS and XMSS |

Entries marked `**[NEW]**` in [ALGO.md](ALGO.md) are planned surfaces to add or expose. They are not claims of completed implementation.

## Library Positioning

<div align="center">
   <img src="assets/readme_library_positioning.svg" alt="NextSSL positioning compared with other crypto libraries" />
</div>

NextSSL is not trying to replace mature production libraries today. Its target is different: archive breadth, explicit profiles, and a contribution model where algorithms can be studied without becoming defaults.

The graph is a project-positioning model, not a benchmark. Established libraries such as OpenSSL, BoringSSL, libsodium, Botan, Crypto++, wolfSSL, and mbedTLS remain far ahead in production maturity, audit history, and deployment.

## Profiles

Profiles are planned as customizable safety policies.

```js
const NP = NextSSL.profile.safest();

NP.default.hash = NextSSL.root.hash.sha256;
NP.default.aead = NextSSL.root.modern["xchacha20-poly1305"];
NP.default.signature = NextSSL.root.modern.ed25519;

// Allowed only as an explicit expert override with policy warnings.
NP.default.hash = NextSSL.root.hash.md5;
```

Planned profile families:

| Profile | Purpose |
| --- | --- |
| `safest` | Conservative defaults for normal users |
| `compatibility` | Legacy and migration support with warnings |
| `research` | Experimental algorithms and review hooks |
| `archive` | Full catalog inspection |
| `pqc` | Post-quantum and hybrid migration work |

## Platform Targets

<div align="center">
   <img src="assets/readme_platform_matrix.svg" alt="NextSSL platform and architecture build matrix" />
</div>

The current `bin` layout contains **29 target variants**:

| Family | Targets |
| --- | --- |
| Android | `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64` |
| iOS | `device-arm64`, `sim-arm64`, `sim-x86_64` |
| Linux glibc | `arm64`, `armv7`, `loongarch64`, `ppc64le`, `riscv64`, `s390x`, `x86`, `x86_64` |
| Linux musl | `arm64`, `armv7`, `x86_64` |
| macOS | `arm64`, `universal`, `x86_64` |
| WASM | `emscripten-wasm32`, `wasi-wasm32` |
| Windows | `arm64-msvc`, `armv7-msvc`, `x86-mingw`, `x86-msvc`, `x86_64-mingw`, `x86_64-msvc` |

Build documentation is still evolving. Start with [BUILD.md](BUILD.md).

## Docs

- [PLAN.md](PLAN.md): roadmap, profiles, lifecycle, safety labels, contribution model.
- [ALGO.md](ALGO.md): complete current inventory and planned surfaces.
- [BUILD.md](BUILD.md): build notes.
- [CONTRIBUTING.md](CONTRIBUTING.md): contribution guide.
- [SECURITY.md](SECURITY.md): security reporting policy.

## Build Target Tags

![android arm64-v8a](https://img.shields.io/badge/android-arm64--v8a-3DDC84?logo=android&logoColor=white)
![android armeabi-v7a](https://img.shields.io/badge/android-armeabi--v7a-3DDC84?logo=android&logoColor=white)
![android x86](https://img.shields.io/badge/android-x86-3DDC84?logo=android&logoColor=white)
![android x86_64](https://img.shields.io/badge/android-x86__64-3DDC84?logo=android&logoColor=white)
![ios device-arm64](https://img.shields.io/badge/ios-device--arm64-111111?logo=apple&logoColor=white)
![ios sim-arm64](https://img.shields.io/badge/ios-sim--arm64-111111?logo=apple&logoColor=white)
![ios sim-x86_64](https://img.shields.io/badge/ios-sim--x86__64-111111?logo=apple&logoColor=white)
![linux glibc arm64](https://img.shields.io/badge/linux--glibc-arm64-FCC624?logo=linux&logoColor=black)
![linux glibc armv7](https://img.shields.io/badge/linux--glibc-armv7-FCC624?logo=linux&logoColor=black)
![linux glibc loongarch64](https://img.shields.io/badge/linux--glibc-loongarch64-FCC624?logo=linux&logoColor=black)
![linux glibc ppc64le](https://img.shields.io/badge/linux--glibc-ppc64le-FCC624?logo=linux&logoColor=black)
![linux glibc riscv64](https://img.shields.io/badge/linux--glibc-riscv64-FCC624?logo=linux&logoColor=black)
![linux glibc s390x](https://img.shields.io/badge/linux--glibc-s390x-FCC624?logo=linux&logoColor=black)
![linux glibc x86](https://img.shields.io/badge/linux--glibc-x86-FCC624?logo=linux&logoColor=black)
![linux glibc x86_64](https://img.shields.io/badge/linux--glibc-x86__64-FCC624?logo=linux&logoColor=black)
![linux musl arm64](https://img.shields.io/badge/linux--musl-arm64-4b5563?logo=linux&logoColor=white)
![linux musl armv7](https://img.shields.io/badge/linux--musl-armv7-4b5563?logo=linux&logoColor=white)
![linux musl x86_64](https://img.shields.io/badge/linux--musl-x86__64-4b5563?logo=linux&logoColor=white)
![macos arm64](https://img.shields.io/badge/macos-arm64-111111?logo=apple&logoColor=white)
![macos universal](https://img.shields.io/badge/macos-universal-111111?logo=apple&logoColor=white)
![macos x86_64](https://img.shields.io/badge/macos-x86__64-111111?logo=apple&logoColor=white)
![wasm emscripten-wasm32](https://img.shields.io/badge/wasm-emscripten--wasm32-654ff0?logo=webassembly&logoColor=white)
![wasm wasi-wasm32](https://img.shields.io/badge/wasm-wasi--wasm32-654ff0?logo=webassembly&logoColor=white)
![windows arm64-msvc](https://img.shields.io/badge/windows-arm64--msvc-0078D4?logo=microsoftwindows&logoColor=white)
![windows armv7-msvc](https://img.shields.io/badge/windows-armv7--msvc-0078D4?logo=microsoftwindows&logoColor=white)
![windows x86-mingw](https://img.shields.io/badge/windows-x86--mingw-0078D4?logo=microsoftwindows&logoColor=white)
![windows x86-msvc](https://img.shields.io/badge/windows-x86--msvc-0078D4?logo=microsoftwindows&logoColor=white)
![windows x86_64-mingw](https://img.shields.io/badge/windows-x86__64--mingw-0078D4?logo=microsoftwindows&logoColor=white)
![windows x86_64-msvc](https://img.shields.io/badge/windows-x86__64--msvc-0078D4?logo=microsoftwindows&logoColor=white)

## Algorithm Tags

![encoding 14](https://img.shields.io/badge/encoding-14-2f7d4f)
![hash 59](https://img.shields.io/badge/hash%20%2F%20KDF--hash-59-6d5796)
![modern 83](https://img.shields.io/badge/modern-83-1f6f9f)
![pqc 41](https://img.shields.io/badge/PQC-41-8f3f62)
![threshold 36](https://img.shields.io/badge/threshold-36-9a5b1f)
![ascon 7](https://img.shields.io/badge/ascon-7-2f6f9f)
![drbg rng 7](https://img.shields.io/badge/DRBG%20%2F%20RNG-7-856404)
![stateful hbs 2](https://img.shields.io/badge/stateful%20HBS-2-4b5563)
![total 249](https://img.shields.io/badge/total%20algorithm%20surfaces-249-24292f)

## Rule

Breadth belongs in the archive. Trust belongs in the defaults.

*NextSSL is building a crypto archive with a seatbelt: wide enough for research, strict enough for users.*
