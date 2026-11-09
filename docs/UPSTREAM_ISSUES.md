# Issues found in upstream libraries

Problems we noticed in code we copy from, kept so we can report them later. Nothing here has been sent to any project.

Before reporting an item: reproduce it in isolation against the upstream's latest version, check its tracker for an
existing report, and use the project's security contact for anything security-relevant. Status "observed" means an
import agent saw it during NextSSL work and it has not been independently reproduced.

| # | Upstream | What we saw | Possible impact | Evidence | Status |
|---|---|---|---|---|---|
| 1 | `ed448-goldilocks` 0.14.0-pre.15 | Signature verification ignores the unused bits of R (Wycheproof Ed448 tcId 63). Our glue now rejects non-zero unused bits in R and A. | Signature malleability, verification accepts a non-canonical encoding | Wycheproof d17cc89f | observed, worked around in glue |
| 2 | sphlib BMW (`pornin/sphlib`) | KAT fails when built with gcc -O2 in Docker. Passes in the default profile and on MSVC. | Possible undefined behaviour giving wrong digests under optimization. Could also be our build. | `bmw` KAT in Docker | observed, cause unknown |
| 3 | `rweather/lightweight-crypto` COMET | Output matches the NIST LWC KAT only for the 33 empty-plaintext vectors. First mismatch at Count 34. | Implementation may not match the submission | NIST LWC submission KAT | observed, not imported |
| 4 | `rweather/lightweight-crypto` ESTATE | Output differs from the NIST KAT at Count 1 (empty message, empty AD). | Implementation may not match the submission | NIST LWC submission KAT | observed, not imported |
| 5 | `hc-256` crate | Matches the 3 author vectors but differs from 286 Crypto++ reference vectors at the first byte. | Either the crate or the vector file is wrong. Unresolved. | Crypto++ test vectors | observed, not imported |
| 6 | `slh-dsa` 0.1.0 | Does not zeroize SK.seed or SK.prf. Does not check a stored key's PK.root against its seeds. | Secrets stay in memory; a corrupted key is not detected | Code reading by agent | observed |
| 7 | `libcrux-hmac-drbg` 0.0.2 | Internal secret state is not fully zeroized. | Secrets stay in memory | Code reading by agent | observed |
| 8 | `tiny-keccak` | Sponge state is not zeroized (affects the KMAC family). | Secrets stay in memory | Code reading by agent | observed |
| 9 | `concat-kdf`, `aegis`, `pwhash` | Internal buffers are not wiped. | Secrets stay in memory | Code reading by agent | observed |
| 10 | C upstreams: SipHash, Ascon, Chaskey, sphlib, HAS-160, MD6 | Key-derived state stays on the stack without wiping. | Secrets stay in memory. Common in reference code, so low value to report. | Code reading by agent | observed |
| 11 | `rweather/skinny-c` | `skinny128-cipher.c` does arithmetic on `const void *`, a GNU extension that MSVC rejects. | Portability only | MSVC build error | observed, blocked here |
| 12 | `chaskey12.c` (mouha.be) | Unaligned, aliased word reads. | Possible undefined behaviour on strict platforms | Code reading by agent | observed |

Already public, for reference and not an achievement of ours: RUSTSEC-2023-0071 (Marvin timing attack) in `rsa` 0.9.x.

## How to add an entry
Add one row with the upstream and its exact version or commit, what was seen, the possible impact, and the evidence.
