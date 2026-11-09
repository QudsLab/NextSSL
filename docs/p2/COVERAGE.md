# P2 coverage: in-scope rows (KEEP, KEEP-PLATFORM, KEEP-PROTOCOL)

Generated 2026-11-08 from `scope_classification.csv`, `docs/p2/STATUS.md`, `algos/*/*/*/algo.toml` and `docs/p2/sources_*.csv`. Scope: 766 rows. DROP rows (10) are excluded from this table.

Status rules, applied in this order per row:
1. ACTIVE: an `algo.toml` matches the row (folder = STATUS path or sources `proposed_path`, or `id`/`aliases` equal the algorithm name after lower-casing and removing non-alphanumerics). Ids are listed.
2. BLOCKED: STATUS.md says `blocked` for the num; the reason is shortened from STATUS.md.
3. PENDING: no algo match and no STATUS line, but a sources CSV row has an upstream (type not `none`). Batch label: `platform` (KEEP-PLATFORM), `protocol` (KEEP-PROTOCOL), `ports` (upstream_type `port`), `P3 advanced` (ZK/HE, threshold/MPC, VDF, advanced primitives), `C-rows` (from `sources_C*.csv`), else `A/B-rows`.
4. NONE: no algo match, no STATUS line, and no sources row with an upstream.

## Summary by status

| Status | KEEP | KEEP-PLATFORM | KEEP-PROTOCOL | Total |
|---|---:|---:|---:|---:|
| ACTIVE | 243 | 1 | 0 | 244 |
| BLOCKED | 120 | 0 | 0 | 120 |
| PENDING | 84 | 0 | 0 | 84 |
| NONE | 211 | 31 | 76 | 318 |
| **Total** | 658 | 32 | 76 | **766** |

## Summary by category

| Category | ACTIVE | BLOCKED | PENDING | NONE | Total |
|---|---:|---:|---:|---:|---:|
| AEAD Algorithms | 36 | 11 | 0 | 24 | 71 |
| Advanced Primitives | 0 | 0 | 0 | 14 | 14 |
| Block Cipher Modes | 7 | 4 | 0 | 0 | 11 |
| DRBG / RNG | 2 | 2 | 5 | 17 | 26 |
| Digital Signatures | 6 | 9 | 13 | 4 | 32 |
| Encoding & Checksum | 21 | 12 | 0 | 1 | 34 |
| Hardware / HSM / TEE | 0 | 0 | 0 | 17 | 17 |
| Hash / Digest / XOF | 61 | 8 | 0 | 6 | 75 |
| Key Agreement / KEM | 6 | 4 | 35 | 6 | 51 |
| Key Derivation Functions | 6 | 18 | 0 | 3 | 27 |
| Lightweight Crypto | 6 | 2 | 0 | 6 | 14 |
| MAC Algorithms | 27 | 4 | 0 | 5 | 36 |
| PKI / Certificates | 0 | 7 | 0 | 33 | 40 |
| PQ Digital Signatures | 15 | 0 | 17 | 7 | 39 |
| Password KDFs | 15 | 4 | 0 | 2 | 21 |
| Protocol Primitives | 0 | 7 | 3 | 40 | 50 |
| Stateful Hash Signatures | 0 | 0 | 6 | 2 | 8 |
| Stream Ciphers | 10 | 11 | 4 | 14 | 39 |
| Symmetric Block Ciphers | 26 | 17 | 1 | 15 | 59 |
| Threshold / MPC | 0 | 0 | 0 | 52 | 52 |
| Verifiable Delay Functions | 0 | 0 | 0 | 3 | 3 |
| ZK Proofs / HE | 0 | 0 | 0 | 47 | 47 |
| **Total** | 244 | 120 | 84 | 318 | **766** |

## PENDING by batch

| Batch | Rows |
|---|---:|
| C-rows | 77 |
| A/B-rows | 2 |
| ports | 5 |
| P3 advanced | 0 |
| platform | 0 |
| protocol | 0 |

## BLOCKED by reason group

Grouping is by keyword in the STATUS.md reason, first match wins in this order: MSVC, >15 files, trait shape, no license / no usable upstream (GPL/AGPL gating, no verifiable source), no KAT (no vector file), other. Rows saying 'same as N' or 'duplicate of N' take the group of row N.

### MSVC (2)

| num | algorithm | reason |
|---:|---|---|
| 122 | catena | medsec/catena@9c89da4 is Linux-only (byteswap.h, unistd.h, /dev/urandom, emmintrin) and does not build on the MSVC host without source edits; its test file only prints ... |
| 188 | skinny | does not build on Windows MSVC: skinny128-cipher.c does arithmetic on `const void *` (GNU extension), which cl.exe rejects; fixing it needs a source edit. Was imported ... |

### >15 files (37)

| num | algorithm | reason |
|---:|---|---|
| 107 | lsh | no KISA C reference found; Crypto++ lsh256.cpp/lsh512.cpp sit on cryptlib.h/secblock.h/misc.h/config*.h/stdcpp.h, transitive set exceeds the 15-file limit |
| 108 | highwayhash | C++ with runtime SIMD dispatch (hh_avx2/sse41/neon/portable + cpuid/arch files), well over 15 files; owner may prefer the highway-hash Rust crate |
| 129 | pbkdf1 | OpenSSL providers/implementations/kdfs/*.c are welded to libcrypto internals (OSSL_PARAM, EVP_MD/EVP_MAC, provider ctx); extracting one needs far more than 15 files. No ... |
| 130 | pkcs12-kdf | same as 129 (mbedtls pkcs12.c alternative needs the md/cipher layers) |
| 131 | evp-bytestokey | same as 129 (evp_key.c needs EVP_MD/EVP_CIPHER) |
| 132 | kdf2 | Botan kdf2.cpp sits on the Botan KDF/hash class tree (>15 files). Alternative: port BouncyCastle KDF2BytesGenerator.java in the port batch |
| 163 | rc6 | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 165 | kasumi | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 166 | safer | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 167 | skipjack | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 170 | xtea | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 171 | tea | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 173 | anubis | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 174 | khazad | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 175 | noekeon | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 179 | shacal-2 | C++ (Botan, Crypto++): the cipher classes depend on the cryptlib/Botan framework headers (more than 15 files) |
| 181 | safer+ | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 198 | hc128 | C++ (Botan, Crypto++): the cipher classes depend on the cryptlib/Botan framework headers (more than 15 files) |
| 205 | aes-ctr-drbg | OpenSSL drbg_ctr.c depends on provider internals (EVP, OSSL_PARAM, drbg framework): far more than 15 files |
| 212 | panama | C++ (Botan, Crypto++): the cipher classes depend on the cryptlib/Botan framework headers (more than 15 files) |
| 214 | seal | C++ (Botan, Crypto++): the cipher classes depend on the cryptlib/Botan framework headers (more than 15 files) |
| 215 | a5/1 | libosmocore a5.c includes osmocom/gsm/a5.h, kasumi.h and crypt/auth.h (libosmocore core headers: more than 15 files); GPL, would need the copyleft feature |
| 216 | a5/2 | libosmocore a5.c includes osmocom/gsm/a5.h, kasumi.h and crypt/auth.h (libosmocore core headers: more than 15 files); GPL, would need the copyleft feature |
| 230 | a5/3 | libosmocore a5.c includes osmocom/gsm/a5.h, kasumi.h and crypt/auth.h (libosmocore core headers: more than 15 files); GPL, would need the copyleft feature |
| 246 | aes-ocb | libtomcrypt ocb3 needs the tomcrypt cipher descriptor tables and headers (more than 15 files) |
| 259 | ocb3 | libtomcrypt ocb3 needs the tomcrypt cipher descriptor tables and headers (more than 15 files) |
| 321 | vmac | Krovetz/Dai reference vmac.c (public domain, fastcrypto.org) needs an external AES (rijndael-alg-fst) and is an unpinned web file; Crypto++ vmac.cpp is >15 files. Not ... |
| 338 | kdf1 | same as 132 (BC KDF1BytesGenerator.java) |
| 353 | kdf-tls12 | same as 129 |
| 355 | kdf-ssh | same as 129 |
| 357 | kdf-ikev2 | same as 129 |
| 358 | kdf-srtp | libsrtp srtp.c is the whole SRTP stack (cipher/auth abstractions); the KDF is not separable within 15 files |
| 361 | kda-twostep | Botan sp800_56c_two_step.cpp depends on Botan KDF/MAC/hash class hierarchy (kdf.h, mac.h, hash.h, ...); transitive set exceeds 15 files |
| 363 | x942-kdf | same as 129 (x942kdf.c needs ASN.1 + EVP) |
| 364 | x963-kdf | same as 129; X9.63 KDF = concat KDF with the counter after Z, take a crate route |
| 372 | evp-bytestokey | duplicate of 131 |
| 373 | kdf2 | duplicate of 132 |

### trait shape (37)

| num | algorithm | reason |
|---:|---|---|
| 12 | pem | PKI structure/label format (KEEP-PROTOCOL, later phase); Encoding trait has no label (PEM type) and decode would drop it |
| 14 | cer | mbedtls asn1parse.c is a BER/DER reader, not CER (X.690 canonical rules not implemented); Encoding trait does not model typed ASN.1 (same reason as der/pkcs rows, ... |
| 15 | pkcs7 | PKCS#7/CMS is a typed PKI structure (KEEP-PROTOCOL, later phase); no matching trait shape |
| 16 | pkcs8 | PKCS#8 is a typed PKI structure (KEEP-PROTOCOL, later phase); no matching trait shape |
| 17 | pkcs12 | PKCS#12 is a typed PKI structure (KEEP-PROTOCOL, later phase); crate is 0.1.0; no matching trait shape |
| 18 | spki | SPKI is a typed PKI structure (KEEP-PROTOCOL, later phase); no matching trait shape |
| 85 | tuplehash128 | Hash trait takes one byte string, TupleHash takes a tuple; needs an owner decision on tuple framing (e.g. length-prefixed items or a separate kind) |
| 86 | tuplehash256 | same as 85 |
| 234 | cfb1 | OpenSSL cfb128.c/cts128.c work through block128_f callbacks over an OpenSSL cipher; the Mode kind is unused and needs a design decision (owner) before importing |
| 239 | cbc-cs1 | OpenSSL cfb128.c/cts128.c work through block128_f callbacks over an OpenSSL cipher; the Mode kind is unused and needs a design decision (owner) before importing |
| 240 | cbc-cs2 | OpenSSL cfb128.c/cts128.c work through block128_f callbacks over an OpenSSL cipher; the Mode kind is unused and needs a design decision (owner) before importing |
| 241 | cbc-cs3 | OpenSSL cfb128.c/cts128.c work through block128_f callbacks over an OpenSSL cipher; the Mode kind is unused and needs a design decision (owner) before importing |
| 359 | kdf-sp800-108 | kbkdf 0.0.1 is RustCrypto but its API fixes the label/context/counter layout; ACVP KDF-1.0 uses caller-supplied fixed data with configurable counter placement and width, ... |
| 366 | bip32-kdf | BIP-32 derivation takes a seed and a derivation path and returns key+chain code; Kdf::derive(ikm, salt, info, out) (salt must be accepted by the registry smoke test) has ... |
| 367 | slip10 | same as 366 (SLIP-0010) |
| 380 | hpke | hpke is a full scheme (KEM+KDF+AEAD, 4 modes, contexts, arbitrary-length messages), not a Kem trait shape; needs a protocol-layer design (owner). RFC 9180 test vectors ... |
| 381 | ecies | same as hpke: ECIES is a hybrid-encryption scheme with arbitrary-length messages, and there is no single standard (variants differ); no standard vector file found |
| 382 | rsa-oaep | RSA encryption transports a caller-chosen message of variable length, which the Kem trait (fixed ss) cannot express; PKCS#1 v1.5 encryption is Bleichenbacher-prone; rsa ... |
| 413 | rsa-pkcs1v15-enc | RSA encryption transports a caller-chosen message of variable length, which the Kem trait (fixed ss) cannot express; PKCS#1 v1.5 encryption is Bleichenbacher-prone; rsa ... |
| 425 | rsa-pkcs1v15-sign | (1) the generic registry smoke test asserts a fixed pk length for every Sign, but RSA keys/signatures are variable length: needs sibling ids per modulus size ... |
| 430 | rsa-pss | (1) the generic registry smoke test asserts a fixed pk length for every Sign, but RSA keys/signatures are variable length: needs sibling ids per modulus size ... |
| 451 | rsa-blind-sig | blind-rsa-signatures is a multi-step protocol (blind, sign blinded, finalize); the Sign trait has no blinding step. RFC 9474 vectors exist. Needs a protocol design |
| 595 | blockchain-vrf | Kind none (no trait yet); vrf 0.2.5 was not checked against RFC 9381. P3 |
| 658 | signal-x3dh | libsignal is not on crates.io; a pinned git dependency drags in its patched curve25519-dalek/boring forks and needs workspace-level dependency changes, and X3DH/double ... |
| 659 | signal-double-ratchet | libsignal is not on crates.io; a pinned git dependency drags in its patched curve25519-dalek/boring forks and needs workspace-level dependency changes, and X3DH/double ... |
| 660 | opaque | multi-message PAKEs; the Kex trait is a single-shot agree(sk, pk). Needs a PAKE/protocol kind (KEEP-PROTOCOL, later phase). pake-cpace 0.1.7 (ISC) was also last updated ... |
| 661 | spake2 | multi-message PAKEs; the Kex trait is a single-shot agree(sk, pk). Needs a PAKE/protocol kind (KEEP-PROTOCOL, later phase). pake-cpace 0.1.7 (ISC) was also last updated ... |
| 668 | pqxdh | libsignal is not on crates.io; a pinned git dependency drags in its patched curve25519-dalek/boring forks and needs workspace-level dependency changes, and X3DH/double ... |
| 669 | cpace | multi-message PAKEs; the Kex trait is a single-shot agree(sk, pk). Needs a PAKE/protocol kind (KEEP-PROTOCOL, later phase). pake-cpace 0.1.7 (ISC) was also last updated ... |
| 689 | srp | multi-message PAKEs; the Kex trait is a single-shot agree(sk, pk). Needs a PAKE/protocol kind (KEEP-PROTOCOL, later phase). pake-cpace 0.1.7 (ISC) was also last updated ... |
| 701 | cms | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 729 | asn1-der | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 730 | asn1-cer | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 731 | asn1-per | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 732 | asn1-oer | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 733 | asn1-xer | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 735 | asn1-ber | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |

### no license / no usable upstream (9)

| num | algorithm | reason |
|---:|---|---|
| 6 | base62 | base62 crate encodes integers (u128), not byte strings, and base62 has no standard alphabet/ordering or published vectors (no source found for a byte-string codec) |
| 109 | mgf1 | no standalone MGF1 anywhere: mbedtls mgf_mask lives in rsa.c (bignum, md, rsa), OpenSSL PKCS1_MGF1 needs EVP_MD; libtomcrypt version needs its hash descriptors. Would be ... |
| 119 | lyra2 | leocalm/Lyra repo has no LICENSE file: no-license sources are not copied |
| 258 | deoxys-ii | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 265 | kiasu | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 280 | aez | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 294 | poet | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 309 | hs1-siv | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 589 | chacha20-drbg | rand_chacha is a stream PRNG, not an SP 800-90A DRBG (no reseed counter, additional input or personalization); no standard to test against. Owner decision |

### no KAT (13)

| num | algorithm | reason |
|---:|---|---|
| 142 | seed | crates.io `seed` is the Rust web framework, not the cipher; the cipher crates are single-author kisaseed 0.1.3 (cipher 0.4 API, contains unsafe) and tc_seed; KAT exists ... |
| 168 | speck | SUPERCOP ref only has CTR stream wrappers (crypto_stream), no raw block API, and no vector file |
| 169 | simon | SUPERCOP ref only has CTR stream wrappers (crypto_stream), no raw block API, and no vector file |
| 199 | hc256 | crate hc-256 0.6.0 reproduces the 3 author vectors (key/IV mostly zero) but DISAGREES with the 286 Crypto++ reference-implementation vectors (random key/IV) already at ... |
| 203 | zuc | zuc 0.4.1 is a single-author crate; no independent ZUC test-vector file could be downloaded (the GSMA eea3eia3zucv16.pdf link returns HTML, Crypto++ has none). Needs a ... |
| 300 | comet | rweather's COMET output differs from the designers' NIST KAT (all three CHAM/Speck variants match only the 33 empty-plaintext vectors; first mismatch at Count 34). Not ... |
| 301 | estate | rweather's ESTATE_TweGIFT-128 differs from the NIST KAT at Count 1 (empty message, empty AD); 1088 of 1089 match. Not shipped until explained |
| 433 | ecdsa-recoverable | no independent vector file found for 65-byte recoverable signatures (ecrecover); k256 recovery would be checked only against itself |
| 436 | sr25519 | schnorrkel 0.11.5 has no published independent vector file (Substrate vectors are generated by the same code); ctx = merlin signing context needs a decision. Could be ... |
| 437 | sm2-sign | the only independent vector is a single OpenSSL signature in the crate's own tests; draft-shen-sm2-ecdsa-02 appendix A uses the 2010 test curve, not sm2p256v1. ... |
| 440 | bbs | bbs 0.4.1 (2020, Hyperledger ursa era) is not the IETF BBS draft and is unmaintained; no vectors |
| 444 | rsa-fdh | rsa-fdh 0.5.0 was last released 2020-11 on the old rsa/digest stack, no independent vectors; same RSA issues as 425 |
| 559 | lea | lea 0.5.4 is a single-author crate on cipher 0.3 with unsafe code; reference vectors exist (Crypto++ lea.txt, KISA lea_vs.c) but there is no reviewed implementation. ... |

### other (22)

| num | algorithm | reason |
|---:|---|---|
| 9 | base85 | base85 0.2 crate (MPL-2.0, contains unsafe uninit buffers) implements a 4-byte-chunk variant with the RFC 1924 alphabet; checked: it gives 5P$#x0000000;;GAPhlz for the ... |
| 13 | der | DER is a typed-structure codec (KEEP-PROTOCOL, later phase); Encoding (bytes<->text) does not model it |
| 22 | crc16-ccitt | 'CRC-16/CCITT' is ambiguous (KERMIT per the reveng alias, IBM-3740/CCITT-FALSE in common usage, X-25, XMODEM...). OWNER DECISION: pick the variant (recommend ... |
| 25 | crc64 | 'CRC-64' is ambiguous (REDIS, ECMA-182, GO-ISO, XZ, WE). ECMA-182 is imported as crc64-ecma (row 26). OWNER DECISION: which variant 'crc64' means |
| 34 | ber | same: typed-structure codec, KEEP-PROTOCOL later phase; mbedtls asn1 also pulls bignum/oid tables |
| 100 | poseidon | needs an owner decision on parameter set and byte<->field-element encoding (BN254/circom?); also pulls arkworks. Not attempted |
| 101 | pedersen-hash | row itself says the owner must choose the generator set; Not attempted |
| 106 | haraka | upstream C is x86 AES-NI only (aesni_ref, immintrin) or ARM NEON; no portable C, would break aarch64/wasm/QEMU builds; accepts only 32/64-byte inputs (not a general ... |
| 172 | gost28147 | gost89.c depends on OpenSSL headers and engine structures |
| 187 | gift | the giftcipher "reference" files are standalone test programs (main, iostream, file I/O), no callable API without editing |
| 201 | sosemanuk | libtomcrypt (same dependency problem) |
| 204 | snow3g | intel-ipsec-mb has only SIMD/assembly SNOW 3G paths, no portable C path |
| 253 | aes-fpe-ff3-1 | fpe 0.7.0 implements only FF1, not FF3-1; no FF3-1 crate checked further |
| 289 | aegis-128 | the original CAESAR AEGIS-128 is not in the aegis crate (only AEGIS-128L/256 and the X2/X4 variants) |
| 317 | hmac-blake2b | hmac 0.13 needs a block-buffered (Eager) hash; blake2 0.11 Blake2b512 (CtOutWrapper) is lazy-buffered, so Hmac<Blake2b512> does not compile (E0271 BufferKind == Eager); ... |
| 318 | hmac-blake2s | same as 317 (Blake2s256); keyed mode imported as blake2s-mac (330) |
| 352 | hkdf-expand-label | HKDF-Expand-Label takes label and context (RFC 8446 section 7.1) which Kdf::derive(ikm, salt, info, out) has no slot for without redefining its inputs, and the label ... |
| 354 | kdf-tls13 | TLS 1.3 key schedule is a multi-step stateful protocol construction (KEEP-PROTOCOL, later phase), not Kdf::derive |
| 365 | noise-kdf | noise-c hashstate.c needs the Noise symmetric-state/hash abstraction; the Noise HKDF is HKDF with split outputs, a protocol composition (KEEP-PROTOCOL), not a primitive |
| 369 | ecdh-kdf | name is ambiguous (the row says so); owner must say which KDF is meant |
| 426 | dsa | variable-length keys with domain parameters (p,q,g) hit the same smoke-test fixed-pk problem as RSA; legacy; Wycheproof dsa_* files exist. Not imported |
| 557 | ascon-xof128 | the ascon-c reference fixes the XOF output at 64 bytes (CRYPTO_BYTES in api.h, no length argument); a variable-length Xof needs an upstream edit, which the rules forbid. ... |

## Full table

| num | algorithm | category | decision | status | detail |
|---:|---|---|---|---|---|
| 1 | base16 | Encoding & Checksum | KEEP | ACTIVE | `base16` |
| 2 | base32 | Encoding & Checksum | KEEP | ACTIVE | `base32` |
| 3 | base32hex | Encoding & Checksum | KEEP | ACTIVE | `base32hex` |
| 4 | base58 | Encoding & Checksum | KEEP | ACTIVE | `base58` |
| 5 | base58check | Encoding & Checksum | KEEP | ACTIVE | `base58check` |
| 6 | base62 | Encoding & Checksum | KEEP | BLOCKED | base62 crate encodes integers (u128), not byte strings, and base62 has no standard alphabet/ordering or published vectors (no source found for a byte-string codec) |
| 7 | base64 | Encoding & Checksum | KEEP | ACTIVE | `base64` |
| 8 | base64url | Encoding & Checksum | KEEP | ACTIVE | `base64url` |
| 9 | base85 | Encoding & Checksum | KEEP | BLOCKED | base85 0.2 crate (MPL-2.0, contains unsafe uninit buffers) implements a 4-byte-chunk variant with the RFC 1924 alphabet; checked: it gives 5P$#x0000000;;GAPhlz for the ... |
| 10 | bech32 | Encoding & Checksum | KEEP | ACTIVE | `bech32` |
| 11 | bech32m | Encoding & Checksum | KEEP | ACTIVE | `bech32m` |
| 12 | pem | Encoding & Checksum | KEEP | BLOCKED | PKI structure/label format (KEEP-PROTOCOL, later phase); Encoding trait has no label (PEM type) and decode would drop it |
| 13 | der | Encoding & Checksum | KEEP | BLOCKED | DER is a typed-structure codec (KEEP-PROTOCOL, later phase); Encoding (bytes<->text) does not model it |
| 14 | cer | Encoding & Checksum | KEEP | BLOCKED | mbedtls asn1parse.c is a BER/DER reader, not CER (X.690 canonical rules not implemented); Encoding trait does not model typed ASN.1 (same reason as der/pkcs rows, ... |
| 15 | pkcs7 | Encoding & Checksum | KEEP | BLOCKED | PKCS#7/CMS is a typed PKI structure (KEEP-PROTOCOL, later phase); no matching trait shape |
| 16 | pkcs8 | Encoding & Checksum | KEEP | BLOCKED | PKCS#8 is a typed PKI structure (KEEP-PROTOCOL, later phase); no matching trait shape |
| 17 | pkcs12 | Encoding & Checksum | KEEP | BLOCKED | PKCS#12 is a typed PKI structure (KEEP-PROTOCOL, later phase); crate is 0.1.0; no matching trait shape |
| 18 | spki | Encoding & Checksum | KEEP | BLOCKED | SPKI is a typed PKI structure (KEEP-PROTOCOL, later phase); no matching trait shape |
| 19 | ff70 | Encoding & Checksum | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 20 | crc8 | Encoding & Checksum | KEEP | ACTIVE | `crc8` |
| 21 | crc16 | Encoding & Checksum | KEEP | ACTIVE | `crc16` |
| 22 | crc16-ccitt | Encoding & Checksum | KEEP | BLOCKED | 'CRC-16/CCITT' is ambiguous (KERMIT per the reveng alias, IBM-3740/CCITT-FALSE in common usage, X-25, XMODEM...). OWNER DECISION: pick the variant (recommend ... |
| 23 | crc32 | Encoding & Checksum | KEEP | ACTIVE | `crc32` |
| 24 | crc32c | Encoding & Checksum | KEEP | ACTIVE | `crc32c` |
| 25 | crc64 | Encoding & Checksum | KEEP | BLOCKED | 'CRC-64' is ambiguous (REDIS, ECMA-182, GO-ISO, XZ, WE). ECMA-182 is imported as crc64-ecma (row 26). OWNER DECISION: which variant 'crc64' means |
| 26 | crc64-ecma | Encoding & Checksum | KEEP | ACTIVE | `crc64-ecma` |
| 27 | adler32 | Encoding & Checksum | KEEP | ACTIVE | `adler32` |
| 28 | fletcher16 | Encoding & Checksum | KEEP | ACTIVE | `fletcher16` |
| 29 | fletcher32 | Encoding & Checksum | KEEP | ACTIVE | `fletcher32` |
| 30 | xxhash32 | Encoding & Checksum | KEEP | ACTIVE | `xxhash32` |
| 31 | xxhash64 | Encoding & Checksum | KEEP | ACTIVE | `xxhash64` |
| 32 | xxh3 | Encoding & Checksum | KEEP | ACTIVE | `xxh3` |
| 33 | base91 | Encoding & Checksum | KEEP | ACTIVE | `base91` |
| 34 | ber | Encoding & Checksum | KEEP | BLOCKED | same: typed-structure codec, KEEP-PROTOCOL later phase; mbedtls asn1 also pulls bignum/oid tables |
| 35 | md2 | Hash / Digest / XOF | KEEP | ACTIVE | `md2` |
| 36 | md4 | Hash / Digest / XOF | KEEP | ACTIVE | `md4` |
| 37 | md5 | Hash / Digest / XOF | KEEP | ACTIVE | `md5` |
| 38 | sha0 | Hash / Digest / XOF | KEEP | ACTIVE | `sha0` |
| 39 | sha1 | Hash / Digest / XOF | KEEP | ACTIVE | `sha1` |
| 40 | gost-r-34.11-94 | Hash / Digest / XOF | KEEP | ACTIVE | `gost-r-34-11-94` |
| 41 | ripemd128 | Hash / Digest / XOF | KEEP | ACTIVE | `ripemd128` |
| 42 | ripemd160 | Hash / Digest / XOF | KEEP | ACTIVE | `ripemd160` |
| 43 | ripemd256 | Hash / Digest / XOF | KEEP | ACTIVE | `ripemd256` |
| 44 | ripemd320 | Hash / Digest / XOF | KEEP | ACTIVE | `ripemd320` |
| 45 | tiger | Hash / Digest / XOF | KEEP | ACTIVE | `tiger` |
| 46 | whirlpool | Hash / Digest / XOF | KEEP | ACTIVE | `whirlpool` |
| 47 | has160 | Hash / Digest / XOF | KEEP | ACTIVE | `has160` |
| 48 | nt-hash | Hash / Digest / XOF | KEEP | ACTIVE | `nt-hash` |
| 49 | lm-hash | Hash / Digest / XOF | KEEP | ACTIVE | `lm-hash` |
| 50 | md6 | Hash / Digest / XOF | KEEP | ACTIVE | `md6` |
| 51 | radio-gatun | Hash / Digest / XOF | KEEP | NONE | no upstream found: no RadioGatun reference repo found; keep none |
| 52 | groestl | Hash / Digest / XOF | KEEP | ACTIVE | `groestl` |
| 53 | jh | Hash / Digest / XOF | KEEP | ACTIVE | `jh` |
| 54 | cubehash | Hash / Digest / XOF | KEEP | ACTIVE | `cubehash` |
| 55 | echo | Hash / Digest / XOF | KEEP | ACTIVE | `echo` |
| 56 | simd | Hash / Digest / XOF | KEEP | ACTIVE | `simd` |
| 57 | fugue | Hash / Digest / XOF | KEEP | ACTIVE | `fugue` |
| 58 | hamsi | Hash / Digest / XOF | KEEP | ACTIVE | `hamsi` |
| 59 | luffa | Hash / Digest / XOF | KEEP | ACTIVE | `luffa` |
| 60 | shabal | Hash / Digest / XOF | KEEP | ACTIVE | `shabal` |
| 61 | bmw | Hash / Digest / XOF | KEEP | ACTIVE | `bmw` |
| 62 | shavite3 | Hash / Digest / XOF | KEEP | ACTIVE | `shavite3` |
| 63 | sha224 | Hash / Digest / XOF | KEEP | ACTIVE | `sha224` |
| 64 | sha256 | Hash / Digest / XOF | KEEP | ACTIVE | `sha256` |
| 65 | sha384 | Hash / Digest / XOF | KEEP | ACTIVE | `sha384` |
| 66 | sha512 | Hash / Digest / XOF | KEEP | ACTIVE | `sha512` |
| 67 | sha512-224 | Hash / Digest / XOF | KEEP | ACTIVE | `sha512-224` |
| 68 | sha512-256 | Hash / Digest / XOF | KEEP | ACTIVE | `sha512-256` |
| 69 | sha3-224 | Hash / Digest / XOF | KEEP | ACTIVE | `sha3-224` |
| 70 | sha3-256 | Hash / Digest / XOF | KEEP | ACTIVE | `sha3-256` |
| 71 | sha3-384 | Hash / Digest / XOF | KEEP | ACTIVE | `sha3-384` |
| 72 | sha3-512 | Hash / Digest / XOF | KEEP | ACTIVE | `sha3-512` |
| 73 | keccak256 | Hash / Digest / XOF | KEEP | ACTIVE | `keccak256` |
| 74 | keccak512 | Hash / Digest / XOF | KEEP | ACTIVE | `keccak512` |
| 75 | shake128 | Hash / Digest / XOF | KEEP | ACTIVE | `shake128` |
| 76 | shake256 | Hash / Digest / XOF | KEEP | ACTIVE | `shake256` |
| 77 | cshake128 | Hash / Digest / XOF | KEEP | ACTIVE | `cshake128` |
| 78 | cshake256 | Hash / Digest / XOF | KEEP | ACTIVE | `cshake256` |
| 79 | kmac128 | Hash / Digest / XOF | KEEP | ACTIVE | `kmac128` |
| 80 | kmac256 | Hash / Digest / XOF | KEEP | ACTIVE | `kmac256` |
| 81 | kmacxof128 | Hash / Digest / XOF | KEEP | ACTIVE | `kmacxof128` |
| 82 | kmacxof256 | Hash / Digest / XOF | KEEP | ACTIVE | `kmacxof256` |
| 83 | parallelhash128 | Hash / Digest / XOF | KEEP | ACTIVE | `parallelhash128` |
| 84 | parallelhash256 | Hash / Digest / XOF | KEEP | ACTIVE | `parallelhash256` |
| 85 | tuplehash128 | Hash / Digest / XOF | KEEP | BLOCKED | Hash trait takes one byte string, TupleHash takes a tuple; needs an owner decision on tuple framing (e.g. length-prefixed items or a separate kind) |
| 86 | tuplehash256 | Hash / Digest / XOF | KEEP | BLOCKED | same as 85 |
| 87 | kangarootwelve | Hash / Digest / XOF | KEEP | ACTIVE | `kangarootwelve` |
| 88 | marsupilami14 | Hash / Digest / XOF | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 89 | blake2b | Hash / Digest / XOF | KEEP | ACTIVE | `blake2b-512` |
| 90 | blake2s | Hash / Digest / XOF | KEEP | ACTIVE | `blake2s` |
| 91 | blake2bp | Hash / Digest / XOF | KEEP | ACTIVE | `blake2bp` |
| 92 | blake2sp | Hash / Digest / XOF | KEEP | ACTIVE | `blake2sp` |
| 93 | blake3 | Hash / Digest / XOF | KEEP | ACTIVE | `blake3` |
| 94 | skein256 | Hash / Digest / XOF | KEEP | ACTIVE | `skein256` |
| 95 | skein512 | Hash / Digest / XOF | KEEP | ACTIVE | `skein512` |
| 96 | skein1024 | Hash / Digest / XOF | KEEP | ACTIVE | `skein1024` |
| 97 | sm3 | Hash / Digest / XOF | KEEP | ACTIVE | `sm3` |
| 98 | streebog256 | Hash / Digest / XOF | KEEP | ACTIVE | `streebog256` |
| 99 | streebog512 | Hash / Digest / XOF | KEEP | ACTIVE | `streebog512` |
| 100 | poseidon | Hash / Digest / XOF | KEEP | BLOCKED | needs an owner decision on parameter set and byte<->field-element encoding (BN254/circom?); also pulls arkworks. Not attempted |
| 101 | pedersen-hash | Hash / Digest / XOF | KEEP | BLOCKED | row itself says the owner must choose the generator set; Not attempted |
| 102 | mimc | Hash / Digest / XOF | KEEP | NONE | no upstream found: arkworks-mimc (8.7k downloads) is below threshold and field-specific; no C reference; keep none |
| 103 | rescue | Hash / Digest / XOF | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 104 | griffin | Hash / Digest / XOF | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 105 | reinforced-concrete | Hash / Digest / XOF | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 106 | haraka | Hash / Digest / XOF | KEEP | BLOCKED | upstream C is x86 AES-NI only (aesni_ref, immintrin) or ARM NEON; no portable C, would break aarch64/wasm/QEMU builds; accepts only 32/64-byte inputs (not a general ... |
| 107 | lsh | Hash / Digest / XOF | KEEP | BLOCKED | no KISA C reference found; Crypto++ lsh256.cpp/lsh512.cpp sit on cryptlib.h/secblock.h/misc.h/config*.h/stdcpp.h, transitive set exceeds the 15-file limit |
| 108 | highwayhash | Hash / Digest / XOF | KEEP | BLOCKED | C++ with runtime SIMD dispatch (hh_avx2/sse41/neon/portable + cpuid/arch files), well over 15 files; owner may prefer the highway-hash Rust crate |
| 109 | mgf1 | Hash / Digest / XOF | KEEP | BLOCKED | no standalone MGF1 anywhere: mbedtls mgf_mask lives in rsa.c (bignum, md, rsa), OpenSSL PKCS1_MGF1 needs EVP_MD; libtomcrypt version needs its hash descriptors. Would be ... |
| 110 | pbkdf2 | Password KDFs | KEEP | ACTIVE | `pbkdf2` |
| 111 | pbkdf2-hmac-sha256 | Password KDFs | KEEP | ACTIVE | `pbkdf2-hmac-sha256` |
| 112 | pbkdf2-hmac-sha512 | Password KDFs | KEEP | ACTIVE | `pbkdf2-hmac-sha512` |
| 113 | bcrypt | Password KDFs | KEEP | ACTIVE | `bcrypt` |
| 114 | scrypt | Password KDFs | KEEP | ACTIVE | `scrypt` |
| 115 | argon2d | Password KDFs | KEEP | ACTIVE | `argon2d` |
| 116 | argon2i | Password KDFs | KEEP | ACTIVE | `argon2i` |
| 117 | argon2id | Password KDFs | KEEP | ACTIVE | `argon2id` |
| 118 | yescrypt | Password KDFs | KEEP | ACTIVE | `yescrypt` |
| 119 | lyra2 | Password KDFs | KEEP | BLOCKED | leocalm/Lyra repo has no LICENSE file: no-license sources are not copied |
| 120 | balloon | Password KDFs | KEEP | ACTIVE | `balloon` |
| 121 | pbkdf2-hmac-sha1 | Password KDFs | KEEP | ACTIVE | `pbkdf2-hmac-sha1` |
| 122 | catena | Password KDFs | KEEP | BLOCKED | medsec/catena@9c89da4 is Linux-only (byteswap.h, unistd.h, /dev/urandom, emmintrin) and does not build on the MSVC host without source edits; its test file only prints ... |
| 123 | pomelo | Password KDFs | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 124 | makwa | Password KDFs | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 125 | bsdicrypt | Password KDFs | KEEP | ACTIVE | `bsdicrypt` |
| 126 | md5crypt | Password KDFs | KEEP | ACTIVE | `md5crypt` |
| 127 | sha256crypt | Password KDFs | KEEP | ACTIVE | `sha256crypt` |
| 128 | sha512crypt | Password KDFs | KEEP | ACTIVE | `sha512crypt` |
| 129 | pbkdf1 | Password KDFs | KEEP | BLOCKED | OpenSSL providers/implementations/kdfs/*.c are welded to libcrypto internals (OSSL_PARAM, EVP_MD/EVP_MAC, provider ctx); extracting one needs far more than 15 files. No ... |
| 130 | pkcs12-kdf | Password KDFs | KEEP | BLOCKED | same as 129 (mbedtls pkcs12.c alternative needs the md/cipher layers) |
| 131 | evp-bytestokey | Key Derivation Functions | KEEP | BLOCKED | same as 129 (evp_key.c needs EVP_MD/EVP_CIPHER) |
| 132 | kdf2 | Key Derivation Functions | KEEP | BLOCKED | Botan kdf2.cpp sits on the Botan KDF/hash class tree (>15 files). Alternative: port BouncyCastle KDF2BytesGenerator.java in the port batch |
| 133 | aes-128 | Symmetric Block Ciphers | KEEP | ACTIVE | `aes-128` |
| 134 | aes-192 | Symmetric Block Ciphers | KEEP | ACTIVE | `aes-192` |
| 135 | aes-256 | Symmetric Block Ciphers | KEEP | ACTIVE | `aes-256` |
| 136 | aria-128 | Symmetric Block Ciphers | KEEP | ACTIVE | `aria-128` |
| 137 | aria-192 | Symmetric Block Ciphers | KEEP | ACTIVE | `aria-192` |
| 138 | aria-256 | Symmetric Block Ciphers | KEEP | ACTIVE | `aria-256` |
| 139 | camellia-128 | Symmetric Block Ciphers | KEEP | ACTIVE | `camellia-128` |
| 140 | camellia-192 | Symmetric Block Ciphers | KEEP | ACTIVE | `camellia-192` |
| 141 | camellia-256 | Symmetric Block Ciphers | KEEP | ACTIVE | `camellia-256` |
| 142 | seed | Symmetric Block Ciphers | KEEP | BLOCKED | crates.io `seed` is the Rust web framework, not the cipher; the cipher crates are single-author kisaseed 0.1.3 (cipher 0.4 API, contains unsafe) and tc_seed; KAT exists ... |
| 143 | sm4 | Symmetric Block Ciphers | KEEP | ACTIVE | `sm4` |
| 144 | kuznyechik | Symmetric Block Ciphers | KEEP | ACTIVE | `kuznyechik` |
| 145 | present | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 146 | led | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 147 | piccolo | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 148 | clefia | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 149 | threefish-256 | Symmetric Block Ciphers | KEEP | ACTIVE | `threefish-256` |
| 150 | threefish-512 | Symmetric Block Ciphers | KEEP | ACTIVE | `threefish-512` |
| 151 | threefish-1024 | Symmetric Block Ciphers | KEEP | ACTIVE | `threefish-1024` |
| 152 | magma | Symmetric Block Ciphers | KEEP | ACTIVE | `magma` |
| 153 | 3des | Symmetric Block Ciphers | KEEP | ACTIVE | `3des` |
| 154 | des | Symmetric Block Ciphers | KEEP | ACTIVE | `des` |
| 155 | blowfish | Symmetric Block Ciphers | KEEP | ACTIVE | `blowfish` |
| 156 | twofish | Symmetric Block Ciphers | KEEP | ACTIVE | `twofish` |
| 157 | serpent | Symmetric Block Ciphers | KEEP | PENDING | A/B-rows: crate serpent=0.6.0 (MIT OR Apache-2.0) [sources_B.csv] |
| 158 | cast5 | Symmetric Block Ciphers | KEEP | ACTIVE | `cast5` |
| 159 | cast6 | Symmetric Block Ciphers | KEEP | ACTIVE | `cast6` |
| 160 | idea | Symmetric Block Ciphers | KEEP | ACTIVE | `idea` |
| 161 | rc2 | Symmetric Block Ciphers | KEEP | ACTIVE | `rc2` |
| 162 | rc5 | Symmetric Block Ciphers | KEEP | ACTIVE | `rc5` |
| 163 | rc6 | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 164 | misty1 | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 165 | kasumi | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 166 | safer | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 167 | skipjack | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 168 | speck | Symmetric Block Ciphers | KEEP | BLOCKED | SUPERCOP ref only has CTR stream wrappers (crypto_stream), no raw block API, and no vector file |
| 169 | simon | Symmetric Block Ciphers | KEEP | BLOCKED | SUPERCOP ref only has CTR stream wrappers (crypto_stream), no raw block API, and no vector file |
| 170 | xtea | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 171 | tea | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 172 | gost28147 | Symmetric Block Ciphers | KEEP | BLOCKED | gost89.c depends on OpenSSL headers and engine structures |
| 173 | anubis | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 174 | khazad | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 175 | noekeon | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 176 | kalyna | Symmetric Block Ciphers | KEEP | ACTIVE | `kalyna`, `kalyna-128-256` |
| 177 | belt | Symmetric Block Ciphers | KEEP | ACTIVE | `belt` |
| 178 | shacal | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 179 | shacal-2 | Symmetric Block Ciphers | KEEP | BLOCKED | C++ (Botan, Crypto++): the cipher classes depend on the cryptlib/Botan framework headers (more than 15 files) |
| 180 | feal | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 181 | safer+ | Symmetric Block Ciphers | KEEP | BLOCKED | libtomcrypt: every cipher includes tomcrypt_private.h, which pulls the 14 tomcrypt headers plus helper sources (more than 15 files) |
| 182 | prince | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 183 | pride | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 184 | twine | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 185 | katan | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 186 | ktantan | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 187 | gift | Symmetric Block Ciphers | KEEP | BLOCKED | the giftcipher "reference" files are standalone test programs (main, iostream, file I/O), no callable API without editing |
| 188 | skinny | Symmetric Block Ciphers | KEEP | BLOCKED | does not build on Windows MSVC: skinny128-cipher.c does arithmetic on `const void *` (GNU extension), which cl.exe rejects; fixing it needs a source edit. Was imported ... |
| 189 | lblock | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 190 | rectangle | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 191 | mmb | Symmetric Block Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 192 | chacha20 | Stream Ciphers | KEEP | ACTIVE | `chacha20` |
| 193 | xchacha20 | Stream Ciphers | KEEP | ACTIVE | `xchacha20` |
| 194 | salsa20 | Stream Ciphers | KEEP | ACTIVE | `salsa20` |
| 195 | xsalsa20 | Stream Ciphers | KEEP | ACTIVE | `xsalsa20` |
| 196 | chacha8 | Stream Ciphers | KEEP | ACTIVE | `chacha8` |
| 197 | chacha12 | Stream Ciphers | KEEP | ACTIVE | `chacha12` |
| 198 | hc128 | Stream Ciphers | KEEP | BLOCKED | C++ (Botan, Crypto++): the cipher classes depend on the cryptlib/Botan framework headers (more than 15 files) |
| 199 | hc256 | Stream Ciphers | KEEP | BLOCKED | crate hc-256 0.6.0 reproduces the 3 author vectors (key/IV mostly zero) but DISAGREES with the 286 Crypto++ reference-implementation vectors (random key/IV) already at ... |
| 200 | rabbit | Stream Ciphers | KEEP | ACTIVE | `rabbit` |
| 201 | sosemanuk | Stream Ciphers | KEEP | BLOCKED | libtomcrypt (same dependency problem) |
| 202 | grain128 | Stream Ciphers | KEEP | PENDING | ports: port https://github.com/bcgit/bc-java (MIT) [sources_B_none_retry2.csv] |
| 203 | zuc | Stream Ciphers | KEEP | BLOCKED | zuc 0.4.1 is a single-author crate; no independent ZUC test-vector file could be downloaded (the GSMA eea3eia3zucv16.pdf link returns HTML, Crypto++ has none). Needs a ... |
| 204 | snow3g | Stream Ciphers | KEEP | BLOCKED | intel-ipsec-mb has only SIMD/assembly SNOW 3G paths, no portable C path |
| 205 | aes-ctr-drbg | Stream Ciphers | KEEP | BLOCKED | OpenSSL drbg_ctr.c depends on provider internals (EVP, OSSL_PARAM, drbg framework): far more than 15 files |
| 206 | rc4 | Stream Ciphers | KEEP | ACTIVE | `rc4` |
| 207 | grainv1 | Stream Ciphers | KEEP | PENDING | ports: port https://github.com/bcgit/bc-java (MIT) [sources_B_none_retry2.csv] |
| 208 | mickeyv2 | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 209 | trivium | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 210 | isaac | Stream Ciphers | KEEP | PENDING | A/B-rows: crate rand_isaac=0.5.1 (MIT OR Apache-2.0) [sources_B_none_retry2.csv] |
| 211 | isaac+ | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 212 | panama | Stream Ciphers | KEEP | BLOCKED | C++ (Botan, Crypto++): the cipher classes depend on the cryptlib/Botan framework headers (more than 15 files) |
| 213 | wake | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 214 | seal | Stream Ciphers | KEEP | BLOCKED | C++ (Botan, Crypto++): the cipher classes depend on the cryptlib/Botan framework headers (more than 15 files) |
| 215 | a5/1 | Stream Ciphers | KEEP | BLOCKED | libosmocore a5.c includes osmocom/gsm/a5.h, kasumi.h and crypt/auth.h (libosmocore core headers: more than 15 files); GPL, would need the copyleft feature |
| 216 | a5/2 | Stream Ciphers | KEEP | BLOCKED | libosmocore a5.c includes osmocom/gsm/a5.h, kasumi.h and crypt/auth.h (libosmocore core headers: more than 15 files); GPL, would need the copyleft feature |
| 217 | e0 | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 218 | salsa20/8 | Stream Ciphers | KEEP | ACTIVE | `salsa20-8` |
| 219 | salsa20/12 | Stream Ciphers | KEEP | ACTIVE | `salsa20-12` |
| 220 | spritz | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 221 | vmpc | Stream Ciphers | KEEP | PENDING | ports: port https://github.com/bcgit/bc-java (MIT) [sources_B_none_retry2.csv] |
| 222 | cryptmt | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 223 | dragon | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 224 | edon80 | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 225 | f-fcsr | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 226 | hermes8 | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 227 | lex | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 228 | nls | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 229 | pomaranch | Stream Ciphers | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 230 | a5/3 | Stream Ciphers | KEEP | BLOCKED | libosmocore a5.c includes osmocom/gsm/a5.h, kasumi.h and crypt/auth.h (libosmocore core headers: more than 15 files); GPL, would need the copyleft feature |
| 231 | ecb | Block Cipher Modes | KEEP | ACTIVE | `aes-128-ecb`, `aes-192-ecb`, `aes-256-ecb` |
| 232 | cbc | Block Cipher Modes | KEEP | ACTIVE | `aes-128-cbc`, `aes-192-cbc`, `aes-256-cbc` |
| 233 | cfb | Block Cipher Modes | KEEP | ACTIVE | `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb` |
| 234 | cfb1 | Block Cipher Modes | KEEP | BLOCKED | OpenSSL cfb128.c/cts128.c work through block128_f callbacks over an OpenSSL cipher; the Mode kind is unused and needs a design decision (owner) before importing |
| 235 | cfb8 | Block Cipher Modes | KEEP | ACTIVE | `aes-128-cfb8`, `aes-192-cfb8`, `aes-256-cfb8` |
| 236 | ofb | Block Cipher Modes | KEEP | ACTIVE | `aes-128-ofb`, `aes-192-ofb`, `aes-256-ofb` |
| 237 | ctr | Block Cipher Modes | KEEP | ACTIVE | `aes-128-ctr`, `aes-192-ctr` |
| 238 | xts | Block Cipher Modes | KEEP | ACTIVE | `aes-128-xts`, `aes-256-xts` |
| 239 | cbc-cs1 | Block Cipher Modes | KEEP | BLOCKED | OpenSSL cfb128.c/cts128.c work through block128_f callbacks over an OpenSSL cipher; the Mode kind is unused and needs a design decision (owner) before importing |
| 240 | cbc-cs2 | Block Cipher Modes | KEEP | BLOCKED | OpenSSL cfb128.c/cts128.c work through block128_f callbacks over an OpenSSL cipher; the Mode kind is unused and needs a design decision (owner) before importing |
| 241 | cbc-cs3 | Block Cipher Modes | KEEP | BLOCKED | OpenSSL cfb128.c/cts128.c work through block128_f callbacks over an OpenSSL cipher; the Mode kind is unused and needs a design decision (owner) before importing |
| 242 | aes-gcm | AEAD Algorithms | KEEP | ACTIVE | `aes-128-gcm`, `aes-192-gcm` |
| 243 | aes-ccm | AEAD Algorithms | KEEP | ACTIVE | `aes-128-ccm`, `aes-128-ccm-8`, `aes-192-ccm`, `aes-256-ccm` |
| 244 | aes-gcm-siv | AEAD Algorithms | KEEP | ACTIVE | `aes-128-gcm-siv`, `aes-256-gcm-siv` |
| 245 | aes-siv | AEAD Algorithms | KEEP | ACTIVE | `aes-siv-cmac-256`, `aes-siv-cmac-512` |
| 246 | aes-ocb | AEAD Algorithms | KEEP | BLOCKED | libtomcrypt ocb3 needs the tomcrypt cipher descriptor tables and headers (more than 15 files) |
| 247 | aes-eax | AEAD Algorithms | KEEP | ACTIVE | `aes-128-eax`, `aes-192-eax`, `aes-256-eax` |
| 248 | aes-kw | AEAD Algorithms | KEEP | ACTIVE | `aes-kw` |
| 249 | aes-kwp | AEAD Algorithms | KEEP | ACTIVE | `aes-kwp` |
| 250 | aes-gmac | AEAD Algorithms | KEEP | ACTIVE | `aes-gmac` |
| 251 | aes-xpn | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 252 | aes-fpe-ff1 | AEAD Algorithms | KEEP | ACTIVE | `aes-fpe-ff1` |
| 253 | aes-fpe-ff3-1 | AEAD Algorithms | KEEP | BLOCKED | fpe 0.7.0 implements only FF1, not FF3-1; no FF3-1 crate checked further |
| 254 | chacha20-poly1305 | AEAD Algorithms | KEEP | ACTIVE | `chacha20-poly1305` |
| 255 | xchacha20-poly1305 | AEAD Algorithms | KEEP | ACTIVE | `xchacha20-poly1305` |
| 256 | aegis128l | AEAD Algorithms | KEEP | ACTIVE | `aegis128l` |
| 257 | aegis256 | AEAD Algorithms | KEEP | ACTIVE | `aegis256` |
| 258 | deoxys-ii | AEAD Algorithms | KEEP | BLOCKED | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 259 | ocb3 | AEAD Algorithms | KEEP | BLOCKED | libtomcrypt ocb3 needs the tomcrypt cipher descriptor tables and headers (more than 15 files) |
| 260 | kccm | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 261 | ascon-aead128 | AEAD Algorithms | KEEP | ACTIVE | `ascon-aead128` |
| 262 | ascon-aead128a | AEAD Algorithms | KEEP | ACTIVE | `ascon-aead128a` |
| 263 | ascon-80pq | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 264 | morus | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 265 | kiasu | AEAD Algorithms | KEEP | BLOCKED | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 266 | marble | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 267 | elephant-dumbo | AEAD Algorithms | KEEP | ACTIVE | `elephant-dumbo` |
| 268 | elephant-jumbo | AEAD Algorithms | KEEP | ACTIVE | `elephant-jumbo` |
| 269 | gift-cofb | AEAD Algorithms | KEEP | ACTIVE | `gift-cofb` |
| 270 | grain-128aead | AEAD Algorithms | KEEP | ACTIVE | `grain-128aead` |
| 271 | isap-a-128a | AEAD Algorithms | KEEP | ACTIVE | `isap-a-128a` |
| 272 | isap-k-128a | AEAD Algorithms | KEEP | ACTIVE | `isap-k-128a` |
| 273 | photon-beetle | AEAD Algorithms | KEEP | ACTIVE | `photon-beetle` |
| 274 | romulus | AEAD Algorithms | KEEP | ACTIVE | `romulus` |
| 275 | sparkle-schwaemm | AEAD Algorithms | KEEP | ACTIVE | `sparkle-schwaemm` |
| 276 | tinyjambu | AEAD Algorithms | KEEP | ACTIVE | `tinyjambu` |
| 277 | xoodyak | AEAD Algorithms | KEEP | ACTIVE | `xoodyak` |
| 278 | colm | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 279 | silc | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 280 | aez | AEAD Algorithms | KEEP | BLOCKED | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 281 | otr-aead | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 282 | cloc | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 283 | jambu | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 284 | icepole | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 285 | ketje | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 286 | keyak | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 287 | norx | AEAD Algorithms | KEEP | ACTIVE | `norx` |
| 288 | acorn | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 289 | aegis-128 | AEAD Algorithms | KEEP | BLOCKED | the original CAESAR AEGIS-128 is not in the aegis crate (only AEGIS-128L/256 and the X2/X4 variants) |
| 290 | rocca | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 291 | rocca-s | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 292 | tiaoxin | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 293 | paeq | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 294 | poet | AEAD Algorithms | KEEP | BLOCKED | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 295 | drygascon | AEAD Algorithms | KEEP | ACTIVE | `drygascon`, `drygascon-256` |
| 296 | subterranean | AEAD Algorithms | KEEP | ACTIVE | `subterranean` |
| 297 | sundae | AEAD Algorithms | KEEP | ACTIVE | `sundae` |
| 298 | spook | AEAD Algorithms | KEEP | ACTIVE | `spook`, `spook-su` |
| 299 | pyjamask | AEAD Algorithms | KEEP | ACTIVE | `pyjamask`, `pyjamask-96` |
| 300 | comet | AEAD Algorithms | KEEP | BLOCKED | rweather's COMET output differs from the designers' NIST KAT (all three CHAM/Speck variants match only the 33 empty-plaintext vectors; first mismatch at Count 34). Not ... |
| 301 | estate | AEAD Algorithms | KEEP | BLOCKED | rweather's ESTATE_TweGIFT-128 differs from the NIST KAT at Count 1 (empty message, empty AD); 1088 of 1089 match. Not shipped until explained |
| 302 | lotus | AEAD Algorithms | KEEP | ACTIVE | `lotus` |
| 303 | locus | AEAD Algorithms | KEEP | ACTIVE | `locus` |
| 304 | spix | AEAD Algorithms | KEEP | ACTIVE | `spix` |
| 305 | orbita | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 306 | saeb | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 307 | mixfeed | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 308 | elmd | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 309 | hs1-siv | AEAD Algorithms | KEEP | BLOCKED | SUPERCOP carries only checksums of its own output, no independent vector file found yet; deoxys-ii and kiasu are GPL-2.0+ (copyleft) |
| 310 | iscream | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 311 | scream | AEAD Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 312 | wage | AEAD Algorithms | KEEP | ACTIVE | `wage` |
| 313 | hmac | MAC Algorithms | KEEP | ACTIVE | `hmac` |
| 314 | hmac-sha256 | MAC Algorithms | KEEP | ACTIVE | `hmac-sha256` |
| 315 | hmac-sha512 | MAC Algorithms | KEEP | ACTIVE | `hmac-sha512` |
| 316 | hmac-sha3-256 | MAC Algorithms | KEEP | ACTIVE | `hmac-sha3-256` |
| 317 | hmac-blake2b | MAC Algorithms | KEEP | BLOCKED | hmac 0.13 needs a block-buffered (Eager) hash; blake2 0.11 Blake2b512 (CtOutWrapper) is lazy-buffered, so Hmac<Blake2b512> does not compile (E0271 BufferKind == Eager); ... |
| 318 | hmac-blake2s | MAC Algorithms | KEEP | BLOCKED | same as 317 (Blake2s256); keyed mode imported as blake2s-mac (330) |
| 319 | aes-cmac | MAC Algorithms | KEEP | ACTIVE | `aes-cmac` |
| 320 | aes-pmac | MAC Algorithms | KEEP | ACTIVE | `aes-pmac` |
| 321 | vmac | MAC Algorithms | KEEP | BLOCKED | Krovetz/Dai reference vmac.c (public domain, fastcrypto.org) needs an external AES (rijndael-alg-fst) and is an unpinned web file; Crypto++ vmac.cpp is >15 files. Not ... |
| 322 | umac | MAC Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 323 | poly1305 | MAC Algorithms | KEEP | ACTIVE | `poly1305` |
| 324 | siphash | MAC Algorithms | KEEP | ACTIVE | `siphash-2-4` |
| 325 | siphash-2-4 | MAC Algorithms | KEEP | ACTIVE | `siphash-2-4` |
| 326 | siphash-4-8 | MAC Algorithms | KEEP | ACTIVE | `siphash-4-8` |
| 327 | kmac128-mac | MAC Algorithms | KEEP | ACTIVE | `kmac128` |
| 328 | kmac256-mac | MAC Algorithms | KEEP | ACTIVE | `kmac256` |
| 329 | blake2b-mac | MAC Algorithms | KEEP | ACTIVE | `blake2b-mac` |
| 330 | blake2s-mac | MAC Algorithms | KEEP | ACTIVE | `blake2s-mac` |
| 331 | blake3-mac | MAC Algorithms | KEEP | ACTIVE | `blake3-mac` |
| 332 | ascon-mac | MAC Algorithms | KEEP | ACTIVE | `ascon-mac` |
| 333 | ascon-prf | MAC Algorithms | KEEP | ACTIVE | `ascon-prf` |
| 334 | ghash | MAC Algorithms | KEEP | ACTIVE | `ghash` |
| 335 | xcbc-mac | MAC Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 336 | cbc-mac | MAC Algorithms | KEEP | ACTIVE | `cbc-mac` |
| 337 | des-mac | MAC Algorithms | KEEP | ACTIVE | `des-mac` |
| 338 | kdf1 | MAC Algorithms | KEEP | BLOCKED | same as 132 (BC KDF1BytesGenerator.java) |
| 339 | hmac-sha3-384 | MAC Algorithms | KEEP | ACTIVE | `hmac-sha3-384` |
| 340 | hmac-sha3-512 | MAC Algorithms | KEEP | ACTIVE | `hmac-sha3-512` |
| 341 | hmac-md5 | MAC Algorithms | KEEP | ACTIVE | `hmac-md5` |
| 342 | hmac-sha1 | MAC Algorithms | KEEP | ACTIVE | `hmac-sha1` |
| 343 | aes-cmac-prf-128 | MAC Algorithms | KEEP | ACTIVE | `aes-cmac-prf-128` |
| 344 | lightmac | MAC Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 345 | chaskey | MAC Algorithms | KEEP | ACTIVE | `chaskey` |
| 346 | emac | MAC Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 347 | tmac | MAC Algorithms | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 348 | omac | MAC Algorithms | KEEP | ACTIVE | `aes-cmac` |
| 349 | hkdf | Key Derivation Functions | KEEP | ACTIVE | `hkdf` |
| 350 | hkdf-expand | Key Derivation Functions | KEEP | ACTIVE | `hkdf-expand` |
| 351 | hkdf-extract | Key Derivation Functions | KEEP | ACTIVE | `hkdf-extract` |
| 352 | hkdf-expand-label | Key Derivation Functions | KEEP | BLOCKED | HKDF-Expand-Label takes label and context (RFC 8446 section 7.1) which Kdf::derive(ikm, salt, info, out) has no slot for without redefining its inputs, and the label ... |
| 353 | kdf-tls12 | Key Derivation Functions | KEEP | BLOCKED | same as 129 |
| 354 | kdf-tls13 | Key Derivation Functions | KEEP | BLOCKED | TLS 1.3 key schedule is a multi-step stateful protocol construction (KEEP-PROTOCOL, later phase), not Kdf::derive |
| 355 | kdf-ssh | Key Derivation Functions | KEEP | BLOCKED | same as 129 |
| 356 | kdf-ikev1 | Key Derivation Functions | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 357 | kdf-ikev2 | Key Derivation Functions | KEEP | BLOCKED | same as 129 |
| 358 | kdf-srtp | Key Derivation Functions | KEEP | BLOCKED | libsrtp srtp.c is the whole SRTP stack (cipher/auth abstractions); the KDF is not separable within 15 files |
| 359 | kdf-sp800-108 | Key Derivation Functions | KEEP | BLOCKED | kbkdf 0.0.1 is RustCrypto but its API fixes the label/context/counter layout; ACVP KDF-1.0 uses caller-supplied fixed data with configurable counter placement and width, ... |
| 360 | kda-onestep | Key Derivation Functions | KEEP | ACTIVE | `concat-kdf` |
| 361 | kda-twostep | Key Derivation Functions | KEEP | BLOCKED | Botan sp800_56c_two_step.cpp depends on Botan KDF/MAC/hash class hierarchy (kdf.h, mac.h, hash.h, ...); transitive set exceeds 15 files |
| 362 | concat-kdf | Key Derivation Functions | KEEP | ACTIVE | `concat-kdf` |
| 363 | x942-kdf | Key Derivation Functions | KEEP | BLOCKED | same as 129 (x942kdf.c needs ASN.1 + EVP) |
| 364 | x963-kdf | Key Derivation Functions | KEEP | BLOCKED | same as 129; X9.63 KDF = concat KDF with the counter after Z, take a crate route |
| 365 | noise-kdf | Key Derivation Functions | KEEP | BLOCKED | noise-c hashstate.c needs the Noise symmetric-state/hash abstraction; the Noise HKDF is HKDF with split outputs, a protocol composition (KEEP-PROTOCOL), not a primitive |
| 366 | bip32-kdf | Key Derivation Functions | KEEP | BLOCKED | BIP-32 derivation takes a seed and a derivation path and returns key+chain code; Kdf::derive(ikm, salt, info, out) (salt must be accepted by the registry smoke test) has ... |
| 367 | slip10 | Key Derivation Functions | KEEP | BLOCKED | same as 366 (SLIP-0010) |
| 368 | sskdf | Key Derivation Functions | KEEP | ACTIVE | `concat-kdf` |
| 369 | ecdh-kdf | Key Derivation Functions | KEEP | BLOCKED | name is ambiguous (the row says so); owner must say which KDF is meant |
| 370 | cmkdf | Key Derivation Functions | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 371 | me-kdf | Key Derivation Functions | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 372 | evp-bytestokey | Key Derivation Functions | KEEP | BLOCKED | duplicate of 131 |
| 373 | kdf2 | Key Derivation Functions | KEEP | BLOCKED | duplicate of 132 |
| 374 | dh | Key Agreement / KEM | KEEP | PENDING | C-rows: cpp https://github.com/weidai11/cryptopp (BSL-1.0) [sources_C_none_retry.csv] |
| 375 | dhp | Key Agreement / KEM | KEEP | PENDING | C-rows: cpp https://github.com/randombit/botan (BSD-2-Clause) [sources_C_none_retry.csv] |
| 376 | ecdh | Key Agreement / KEM | KEEP | ACTIVE | `ecdh-p256`, `ecdh-p384`, `ecdh-p521` |
| 377 | x25519 | Key Agreement / KEM | KEEP | ACTIVE | `x25519` |
| 378 | x448 | Key Agreement / KEM | KEEP | ACTIVE | `x448` |
| 379 | x3dh | Key Agreement / KEM | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 380 | hpke | Key Agreement / KEM | KEEP | BLOCKED | hpke is a full scheme (KEM+KDF+AEAD, 4 modes, contexts, arbitrary-length messages), not a Kem trait shape; needs a protocol-layer design (owner). RFC 9180 test vectors ... |
| 381 | ecies | Key Agreement / KEM | KEEP | BLOCKED | same as hpke: ECIES is a hybrid-encryption scheme with arbitrary-length messages, and there is no single standard (variants differ); no standard vector file found |
| 382 | rsa-oaep | Key Agreement / KEM | KEEP | BLOCKED | RSA encryption transports a caller-chosen message of variable length, which the Kem trait (fixed ss) cannot express; PKCS#1 v1.5 encryption is Bleichenbacher-prone; rsa ... |
| 383 | csidh | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/ioerror/csidh-reference-implementation (NOASSERTION (README says public domain)) [sources_C.csv] |
| 384 | frodokem | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/microsoft/PQCrypto-LWEKE (MIT) [sources_C.csv] |
| 385 | kyber | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/pq-crystals/kyber (CC0-1.0 OR Apache-2.0) [sources_C.csv] |
| 386 | ml-kem-512 | Key Agreement / KEM | KEEP | ACTIVE | `ml-kem-512` |
| 387 | ml-kem-768 | Key Agreement / KEM | KEEP | ACTIVE | `ml-kem-768` |
| 388 | ml-kem-1024 | Key Agreement / KEM | KEEP | ACTIVE | `ml-kem-1024` |
| 389 | ntru | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/open-quantum-safe/liboqs (MIT (liboqs; third-party subfolders keep their own license)) [sources_C.csv] |
| 390 | ntruprime | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/open-quantum-safe/liboqs (MIT (liboqs; third-party subfolders keep their own license)) [sources_C.csv] |
| 391 | sntrup761 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/open-quantum-safe/liboqs (MIT (liboqs; third-party subfolders keep their own license)) [sources_C.csv] |
| 392 | classic-mceliece | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT); repo has no top-level LICENSE) [sources_C.csv] |
| 393 | mceliece-348864 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 394 | mceliece-348864f | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 395 | mceliece-460896 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 396 | mceliece-460896f | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 397 | mceliece-6688128 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 398 | mceliece-6688128f | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 399 | mceliece-6960119 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 400 | mceliece-6960119f | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 401 | mceliece-8192128 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 402 | mceliece-8192128f | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (public domain / CC0 / MIT)) [sources_C.csv] |
| 403 | bike-1 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/awslabs/bike-kem (Apache-2.0) [sources_C.csv] |
| 404 | bike-3 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/awslabs/bike-kem (Apache-2.0) [sources_C.csv] |
| 405 | bike-5 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/awslabs/bike-kem (Apache-2.0) [sources_C.csv] |
| 406 | hqc-128 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (PQClean)) [sources_C.csv] |
| 407 | hqc-192 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (PQClean)) [sources_C.csv] |
| 408 | hqc-256 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (PQClean)) [sources_C.csv] |
| 409 | ntruhps2048677 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/open-quantum-safe/liboqs (MIT (liboqs; third-party subfolders keep their own license)) [sources_C.csv] |
| 410 | ntruhps4096821 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/open-quantum-safe/liboqs (MIT (liboqs; third-party subfolders keep their own license)) [sources_C.csv] |
| 411 | ntruhrss701 | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/open-quantum-safe/liboqs (MIT (liboqs; third-party subfolders keep their own license)) [sources_C.csv] |
| 412 | ecmqv | Key Agreement / KEM | KEEP | PENDING | ports: port https://github.com/bcgit/bc-java (MIT) [sources_C_none_retry.csv] |
| 413 | rsa-pkcs1v15-enc | Key Agreement / KEM | KEEP | BLOCKED | RSA encryption transports a caller-chosen message of variable length, which the Kem trait (fixed ss) cannot express; PKCS#1 v1.5 encryption is Bleichenbacher-prone; rsa ... |
| 414 | elgamal | Key Agreement / KEM | KEEP | PENDING | C-rows: cpp https://github.com/weidai11/cryptopp (BSL-1.0) [sources_C_none_retry.csv] |
| 415 | sike | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/microsoft/PQCrypto-SIDH (MIT) [sources_C.csv] |
| 416 | saber | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/KULeuven-COSIC/SABER (LicenseRef-Public-Domain (per LICENSE file)) [sources_C.csv] |
| 417 | newhope | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/newhopecrypto/newhope (NONE (no license detected)) [sources_C.csv] |
| 418 | round5 | Key Agreement / KEM | KEEP | NONE | no upstream found: official Round5 submission is a NIST zip; not a git repo; so no 40-hex pin; r5embed/r5embed is an unofficial heavily modified fork with NOASSERTION ... |
| 419 | lac | Key Agreement / KEM | KEEP | NONE | no upstream found: no LAC submission repo found in search; keep none |
| 420 | ledacrypt | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/LEDAcrypt/LEDAcrypt (NOASSERTION (LICENSE file present; read it)) [sources_C.csv] |
| 421 | nts-kem | Key Agreement / KEM | KEEP | PENDING | C-rows: c https://github.com/post-quantum/nts-kem (NONE (no license detected)) [sources_C.csv] |
| 422 | rollo | Key Agreement / KEM | KEEP | NONE | no upstream found: official ROLLO submission is a NIST zip; the constant-time code is a third-party fork (peacker/constant_time_rollo); not the authors' repo; keep none |
| 423 | rqc | Key Agreement / KEM | KEEP | NONE | no upstream found: official RQC spec and NIST zip only; no git repo with a verified license found; keep none |
| 424 | ntru+ | Key Agreement / KEM | KEEP | NONE | no upstream found: NTRU+ reference code not found in search; sntrup crates are NTRU Prime; a different scheme; keep none |
| 425 | rsa-pkcs1v15-sign | Digital Signatures | KEEP | BLOCKED | (1) the generic registry smoke test asserts a fixed pk length for every Sign, but RSA keys/signatures are variable length: needs sibling ids per modulus size ... |
| 426 | dsa | Digital Signatures | KEEP | BLOCKED | variable-length keys with domain parameters (p,q,g) hit the same smoke-test fixed-pk problem as RSA; legacy; Wycheproof dsa_* files exist. Not imported |
| 427 | gost-r-34.10-2001 | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/gost-engine/engine (Apache-2.0 (per GitHub)) [sources_C.csv] |
| 428 | rainbow | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/fast-crypto-lab/rainbow-submission-round2 (NOASSERTION (license.txt states CC0-1.0 waiver)) [sources_C.csv] |
| 429 | ge-mss | Digital Signatures | KEEP | NONE | no upstream found: GeMSS code is only on LIP6 project pages (not git); so no 40-hex pin possible; keep none |
| 430 | rsa-pss | Digital Signatures | KEEP | BLOCKED | (1) the generic registry smoke test asserts a fixed pk length for every Sign, but RSA keys/signatures are variable length: needs sibling ids per modulus size ... |
| 431 | ecdsa | Digital Signatures | KEEP | ACTIVE | `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521` |
| 432 | det-ecdsa | Digital Signatures | KEEP | ACTIVE | `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521` |
| 433 | ecdsa-recoverable | Digital Signatures | KEEP | BLOCKED | no independent vector file found for 65-byte recoverable signatures (ecrecover); k256 recovery would be checked only against itself |
| 434 | ed25519 | Digital Signatures | KEEP | ACTIVE | `ed25519` |
| 435 | ed448 | Digital Signatures | KEEP | ACTIVE | `ed448` |
| 436 | sr25519 | Digital Signatures | KEEP | BLOCKED | schnorrkel 0.11.5 has no published independent vector file (Substrate vectors are generated by the same code); ctx = merlin signing context needs a decision. Could be ... |
| 437 | sm2-sign | Digital Signatures | KEEP | BLOCKED | the only independent vector is a single OpenSSL signature in the crate's own tests; draft-shen-sm2-ecdsa-02 appendix A uses the 2010 test curve, not sm2p256v1. ... |
| 438 | gost-r-34.10-2012 | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/gost-engine/engine (Apache-2.0 (per GitHub)) [sources_C.csv] |
| 439 | schnorr | Digital Signatures | KEEP | ACTIVE | `schnorr-bip340` |
| 440 | bbs | Digital Signatures | KEEP | BLOCKED | bbs 0.4.1 (2020, Hyperledger ursa era) is not the IETF BBS draft and is unmaintained; no vectors |
| 441 | bls12-381-g1 | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/supranational/blst (Apache-2.0) [sources_C.csv] |
| 442 | bls12-381-g2 | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/supranational/blst (Apache-2.0) [sources_C.csv] |
| 443 | ecdsa-secp256k1 | Digital Signatures | KEEP | ACTIVE | `ecdsa-secp256k1` |
| 444 | rsa-fdh | Digital Signatures | KEEP | BLOCKED | rsa-fdh 0.5.0 was last released 2020-11 on the old rsa/digest stack, no independent vectors; same RSA issues as 425 |
| 445 | kcdsa | Digital Signatures | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 446 | ecgdsa | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/ANSSI-FR/libecc (NOASSERTION (dual BSD / GPLv2 per LICENSE)) [sources_C.csv] |
| 447 | eckdsa | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/ANSSI-FR/libecc (NOASSERTION (dual BSD / GPLv2 per LICENSE)) [sources_C.csv] |
| 448 | musig | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/bitcoin-core/secp256k1 (MIT) [sources_C.csv] |
| 449 | musig2 | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/bitcoin-core/secp256k1 (MIT) [sources_C.csv] |
| 450 | bls-aggregate | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/supranational/blst (Apache-2.0) [sources_C.csv] |
| 451 | rsa-blind-sig | Digital Signatures | KEEP | BLOCKED | blind-rsa-signatures is a multi-step protocol (blind, sign blinded, finalize); the Sign trait has no blinding step. RFC 9474 vectors exist. Needs a protocol design |
| 452 | bls-blind-sig | Digital Signatures | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 453 | cryptonote-ring-sig | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/monero-project/monero (BSD-3-Clause) [sources_C.csv] |
| 454 | mlsag | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/monero-project/monero (BSD-3-Clause) [sources_C.csv] |
| 455 | clsag | Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/monero-project/monero (BSD-3-Clause) [sources_C.csv] |
| 456 | group-sig | Digital Signatures | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 457 | dilithium | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/pq-crystals/dilithium (CC0-1.0 OR Apache-2.0 OR GPL-2.0-only) [sources_C.csv] |
| 458 | ml-dsa-44 | PQ Digital Signatures | KEEP | ACTIVE | `ml-dsa-44` |
| 459 | ml-dsa-65 | PQ Digital Signatures | KEEP | ACTIVE | `ml-dsa-65` |
| 460 | ml-dsa-87 | PQ Digital Signatures | KEEP | ACTIVE | `ml-dsa-87` |
| 461 | falcon-512 | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (PQClean)) [sources_C.csv] |
| 462 | falcon-1024 | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (PQClean)) [sources_C.csv] |
| 463 | falcon-padded-512 | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (PQClean)) [sources_C.csv] |
| 464 | falcon-padded-1024 | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/PQClean/PQClean (per-scheme (PQClean)) [sources_C.csv] |
| 465 | sphincs+ | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/sphincs/sphincsplus (LicenseRef-SPHINCS-PLUS-Public-Domain OR CC0-1.0 OR 0BSD OR MIT-0 (AND MIT)) [sources_C.csv] |
| 466 | slh-dsa-sha2-128f | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-sha2-128f` |
| 467 | slh-dsa-sha2-128s | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-sha2-128s` |
| 468 | slh-dsa-sha2-192f | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-sha2-192f` |
| 469 | slh-dsa-sha2-192s | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-sha2-192s` |
| 470 | slh-dsa-sha2-256f | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-sha2-256f` |
| 471 | slh-dsa-sha2-256s | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-sha2-256s` |
| 472 | slh-dsa-shake-128f | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-shake-128f` |
| 473 | slh-dsa-shake-128s | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-shake-128s` |
| 474 | slh-dsa-shake-192f | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-shake-192f` |
| 475 | slh-dsa-shake-192s | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-shake-192s` |
| 476 | slh-dsa-shake-256f | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-shake-256f` |
| 477 | slh-dsa-shake-256s | PQ Digital Signatures | KEEP | ACTIVE | `slh-dsa-shake-256s` |
| 478 | haetae | PQ Digital Signatures | KEEP | NONE | no upstream found: HAETAE reference code not found on GitHub; only the paper is verified; keep none |
| 479 | almar | PQ Digital Signatures | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 480 | picnic | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/isec-tugraz/Picnic (MIT) [sources_C.csv] |
| 481 | uov | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/open-quantum-safe/liboqs (MIT (liboqs; third-party subfolders keep their own license)) [sources_C.csv] |
| 482 | mayo | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/PQCMayo/MAYO-C (Apache-2.0) [sources_C.csv] |
| 483 | prov | PQ Digital Signatures | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 484 | sqisign | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/SQISign/the-sqisign (Apache-2.0) [sources_C.csv] |
| 485 | hawk | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/hawk-sign/dev (MIT) [sources_C_none_retry.csv] |
| 486 | hufu | PQ Digital Signatures | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 487 | sdith | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/open-quantum-safe/liboqs (MIT (liboqs; third-party subfolders keep their own license)) [sources_C.csv] |
| 488 | less | PQ Digital Signatures | KEEP | NONE | no upstream found: GMUCERG/LESS is a hardware implementation with no license; no reference C repo found; keep none |
| 489 | meds | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/MEDSpqc/meds (GPL-3.0) [sources_C_none_retry.csv] |
| 490 | cross | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/open-quantum-safe/liboqs (MIT (liboqs; third-party subfolders keep their own license)) [sources_C.csv] |
| 491 | wave | PQ Digital Signatures | KEEP | NONE | no upstream found: WAVE portable C reference is only on wave-sign.org; not a verified git repo; keep none |
| 492 | gravity-sphincs | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/gravity-postquantum/gravity-sphincs (NONE (README says Apache-2.0; no LICENSE file)) [sources_C.csv] |
| 493 | wots+ | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/XMSS/xmss-reference (CC0-1.0) [sources_C.csv] |
| 494 | fors | PQ Digital Signatures | KEEP | PENDING | C-rows: c https://github.com/sphincs/sphincsplus (LicenseRef-SPHINCS-PLUS-Public-Domain OR CC0-1.0 OR 0BSD OR MIT-0 (AND MIT)) [sources_C.csv] |
| 495 | hors | PQ Digital Signatures | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 496 | lms | Stateful Hash Signatures | KEEP | PENDING | C-rows: c https://github.com/cisco/hash-sigs (NOASSERTION (Cisco BSD-style license in license.txt; confirm SPDX)) [sources_C.csv] |
| 497 | hss | Stateful Hash Signatures | KEEP | PENDING | C-rows: c https://github.com/cisco/hash-sigs (NOASSERTION (Cisco BSD-style license in license.txt; confirm SPDX)) [sources_C.csv] |
| 498 | xmss | Stateful Hash Signatures | KEEP | PENDING | C-rows: c https://github.com/XMSS/xmss-reference (CC0-1.0) [sources_C.csv] |
| 499 | xmssmt | Stateful Hash Signatures | KEEP | PENDING | C-rows: c https://github.com/XMSS/xmss-reference (CC0-1.0) [sources_C.csv] |
| 500 | gmss | Stateful Hash Signatures | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 501 | xmss-t | Stateful Hash Signatures | KEEP | PENDING | C-rows: c https://github.com/XMSS/xmss-reference (CC0-1.0) [sources_C.csv] |
| 502 | bpqs | Stateful Hash Signatures | KEEP | NONE | no upstream found: corda/bpqs repo exists (archived) but license is NOASSERTION; no verifiable license; no crate; keep none (no license) |
| 503 | wots | Stateful Hash Signatures | KEEP | PENDING | C-rows: c https://github.com/XMSS/xmss-reference (CC0-1.0) [sources_C.csv] |
| 504 | frost | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 505 | tbls | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 506 | gargos | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 507 | tecla | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 508 | the-clash | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 509 | classic-schnorr-t | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 510 | bam | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 511 | ccgmp | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 512 | haystack | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 513 | mithril | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 514 | quorus | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 515 | redeta | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 516 | splitkey | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 517 | minimpc | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 518 | maestro | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 519 | amber | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 520 | hermine | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 521 | least | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 522 | tanuki | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 523 | vinaigrette | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 524 | pantheria | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 525 | zama-tfhe | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 526 | zama-zhenith | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 527 | piver | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 528 | schmivitz | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 529 | smallwood | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 530 | shamir | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 531 | feldman-vss | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 532 | pedersen-vss | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 533 | dkg | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 534 | pvss | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 535 | ot | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 536 | vole | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 537 | beaver | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 538 | mpc-ecdsa | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 539 | mpc-schnorr | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 540 | roast | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 541 | gg18 | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 542 | gg20 | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 543 | gg21 | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 544 | cmp | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 545 | lindell17 | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 546 | doerner-shelat | Threshold / MPC | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 547 | spdz | Threshold / MPC | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 548 | mascot | Threshold / MPC | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 549 | bmr | Threshold / MPC | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 550 | gmw | Threshold / MPC | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 551 | proactive-ss | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 552 | async-dkg | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 553 | robust-dkg | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 554 | ring-sig-generic | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 555 | linkable-ring-sig | Threshold / MPC | KEEP | NONE | no upstream found: no source row |
| 556 | ascon-hash256 | Lightweight Crypto | KEEP | ACTIVE | `ascon-hash256` |
| 557 | ascon-xof128 | Lightweight Crypto | KEEP | BLOCKED | the ascon-c reference fixes the XOF output at 64 bytes (CRYPTO_BYTES in api.h, no length argument); a variable-length Xof needs an upstream edit, which the rules forbid. ... |
| 558 | ascon-cxof128 | Lightweight Crypto | KEEP | ACTIVE | `ascon-cxof128` |
| 559 | lea | Lightweight Crypto | KEEP | BLOCKED | lea 0.5.4 is a single-author crate on cipher 0.3 with unsafe code; reference vectors exist (Crypto++ lea.txt, KISA lea_vs.c) but there is no reviewed implementation. ... |
| 560 | hight | Lightweight Crypto | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 561 | photon-beetle-hash | Lightweight Crypto | KEEP | ACTIVE | `photon-beetle-hash` |
| 562 | romulus-hash | Lightweight Crypto | KEEP | ACTIVE | `romulus-hash` |
| 563 | sparkle-esch | Lightweight Crypto | KEEP | ACTIVE | `sparkle-esch` |
| 564 | xoodyak-hash | Lightweight Crypto | KEEP | ACTIVE | `xoodyak-hash` |
| 565 | mibs | Lightweight Crypto | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 566 | klein | Lightweight Crypto | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 567 | puffin | Lightweight Crypto | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 568 | spongent | Lightweight Crypto | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 569 | quark | Lightweight Crypto | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 570 | ctr-drbg | DRBG / RNG | KEEP | PENDING | C-rows: c https://github.com/openssl/openssl (Apache-2.0) [sources_C.csv] |
| 571 | hash-drbg | DRBG / RNG | KEEP | PENDING | C-rows: c https://github.com/openssl/openssl (Apache-2.0) [sources_C.csv] |
| 572 | hmac-drbg | DRBG / RNG | KEEP | ACTIVE | `hmac-drbg-sha256` |
| 573 | csprng-system | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 574 | trng | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 575 | entropy-pool | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 576 | reseed-scheduler | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 577 | rdrand | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 578 | rdseed | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 579 | jitterentropy | DRBG / RNG | KEEP | PENDING | C-rows: c https://github.com/smuellerDD/jitterentropy-library (BSD-3-Clause OR GPL-2.0-only (LICENSE.bsd present; use BSD option)) [sources_C.csv] |
| 580 | fortuna | DRBG / RNG | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 581 | nist-sp800-90b | DRBG / RNG | KEEP | PENDING | C-rows: c https://github.com/usnistgov/SP800-90B_EntropyAssessment (NONE (no LICENSE file; likely US government work; to confirm)) [sources_C.csv] |
| 582 | nist-sp800-90c | DRBG / RNG | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 583 | haveged | DRBG / RNG | KEEP | PENDING | C-rows: c https://github.com/jirka-h/haveged (GPL-3.0) [sources_C.csv] |
| 584 | yarrow | DRBG / RNG | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 585 | cryptgenrandom | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 586 | egd | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 587 | prngd | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 588 | lavarnd | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 589 | chacha20-drbg | DRBG / RNG | KEEP | BLOCKED | rand_chacha is a stream PRNG, not an SP 800-90A DRBG (no reseed counter, additional input or personalization); no standard to test against. Owner decision |
| 590 | getrandom | DRBG / RNG | KEEP-PLATFORM | ACTIVE | `os-entropy` |
| 591 | getentropy | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 592 | bcryptgenrandom | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 593 | nist-randomness-beacon | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 594 | qrng | DRBG / RNG | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 595 | blockchain-vrf | DRBG / RNG | KEEP | BLOCKED | Kind none (no trait yet); vrf 0.2.5 was not checked against RFC 9381. P3 |
| 596 | groth16 | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 597 | plonk | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 598 | marlin | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 599 | halo2 | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 600 | plonky2 | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 601 | stark | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 602 | bulletproofs | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 603 | spartan | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 604 | sonic | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 605 | kzg-commitment | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 606 | fri | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 607 | ligero | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 608 | dory | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 609 | gm17 | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 610 | tfhe | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 611 | pinocchio | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 612 | supersonic | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 613 | bgv | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 614 | ckks | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 615 | bfv | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 616 | gsw | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 617 | dm-cggi | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 618 | nova | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 619 | supernova | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 620 | hypernova | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 621 | protostar | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 622 | shplonk | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 623 | ipa | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 624 | brakedown | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 625 | orion | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 626 | stir | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 627 | whir | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 628 | basefold | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 629 | gemini | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 630 | latticefold | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 631 | jolt | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 632 | sp1 | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 633 | lasso | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 635 | risc-zero | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 636 | ggpr | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 637 | bctv14 | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 638 | pghr13 | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 639 | hyrax | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 640 | libra | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 641 | virgo | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 642 | fractal | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 643 | aurora | ZK Proofs / HE | KEEP | NONE | no upstream found: no source row |
| 645 | noise-nn | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 646 | noise-kn | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 647 | noise-nk | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 648 | noise-kk | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 649 | noise-nx | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 650 | noise-xn | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 651 | noise-xk | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 652 | noise-kx | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 653 | noise-in | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 654 | noise-ik | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 655 | noise-ix | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 656 | noise-xx | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 657 | noise-ikpsk2 | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 658 | signal-x3dh | Protocol Primitives | KEEP | BLOCKED | libsignal is not on crates.io; a pinned git dependency drags in its patched curve25519-dalek/boring forks and needs workspace-level dependency changes, and X3DH/double ... |
| 659 | signal-double-ratchet | Protocol Primitives | KEEP | BLOCKED | libsignal is not on crates.io; a pinned git dependency drags in its patched curve25519-dalek/boring forks and needs workspace-level dependency changes, and X3DH/double ... |
| 660 | opaque | Protocol Primitives | KEEP | BLOCKED | multi-message PAKEs; the Kex trait is a single-shot agree(sk, pk). Needs a PAKE/protocol kind (KEEP-PROTOCOL, later phase). pake-cpace 0.1.7 (ISC) was also last updated ... |
| 661 | spake2 | Protocol Primitives | KEEP | BLOCKED | multi-message PAKEs; the Kex trait is a single-shot agree(sk, pk). Needs a PAKE/protocol kind (KEEP-PROTOCOL, later phase). pake-cpace 0.1.7 (ISC) was also last updated ... |
| 662 | spake2+ | Protocol Primitives | KEEP | PENDING | C-rows: cpp https://github.com/randombit/botan (BSD-2-Clause) [sources_C_none_retry.csv] |
| 663 | dragonfly | Protocol Primitives | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 664 | otrv4 | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 665 | mtproto | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 666 | wireguard | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 667 | mls | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 668 | pqxdh | Protocol Primitives | KEEP | BLOCKED | libsignal is not on crates.io; a pinned git dependency drags in its patched curve25519-dalek/boring forks and needs workspace-level dependency changes, and X3DH/double ... |
| 669 | cpace | Protocol Primitives | KEEP | BLOCKED | multi-message PAKEs; the Kex trait is a single-shot agree(sk, pk). Needs a PAKE/protocol kind (KEEP-PROTOCOL, later phase). pake-cpace 0.1.7 (ISC) was also last updated ... |
| 670 | aucpace | Protocol Primitives | KEEP | NONE | no upstream found: BjoernMHaase/AuCPace has no license; RustCrypto aucpace crate has 4.4k downloads (below 10k threshold); keep none (no license or below threshold) |
| 671 | kemtls | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 672 | pq-tls-hybrid | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 673 | ech | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 674 | odohdtls | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 675 | oblivious-http | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 676 | privacy-pass | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 678 | edhoc | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 679 | oscore | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 680 | dtls12 | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 681 | dtls13 | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 682 | noise-xxfallback | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 683 | disco | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 684 | noisesocket | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 685 | zrtp | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 686 | hmqv | Protocol Primitives | KEEP | PENDING | C-rows: cpp https://github.com/weidai11/cryptopp (BSL-1.0) [sources_C_none_retry.csv] |
| 687 | yak | Protocol Primitives | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 688 | sesame | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 689 | srp | Protocol Primitives | KEEP | BLOCKED | multi-message PAKEs; the Kex trait is a single-shot agree(sk, pk). Needs a PAKE/protocol kind (KEEP-PROTOCOL, later phase). pake-cpace 0.1.7 (ISC) was also last updated ... |
| 690 | j-pake | Protocol Primitives | KEEP | PENDING | ports: port https://github.com/bcgit/bc-java (MIT) [sources_C_none_retry.csv] |
| 691 | otr | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 692 | speke | Protocol Primitives | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 693 | curvecp | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 694 | minimalt | Protocol Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 695 | sts | Protocol Primitives | KEEP | NONE | no upstream found: no verifiable upstream found (crates.io and GitHub search; Botan/Crypto++/Bouncy Castle trees; official submission pages); no license-verified source; ... |
| 696 | x509v3 | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 697 | crl | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 698 | ocsp | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 699 | ocsp-stapling | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 700 | csr | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 701 | cms | PKI / Certificates | KEEP | BLOCKED | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 702 | scep | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 703 | est | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 704 | acme | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 705 | ct | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 706 | mft | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 707 | roa | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 708 | tal | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 709 | rfc822name | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 710 | ipaddress | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 711 | subjectaltname | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 712 | authoritykeyid | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 713 | subjectkeyid | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 714 | keyusage | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 715 | extendedkeyusage | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 716 | basicconstraints | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 717 | nameconstraints | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 718 | cdp | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 719 | aia | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 720 | ocsp-nocheck | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 721 | precert-poison | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 722 | sct | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 723 | tls-features | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 724 | signed-timestamp | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 725 | tsp | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 726 | cades | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 727 | pades | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 728 | xades | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 729 | asn1-der | PKI / Certificates | KEEP | BLOCKED | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 730 | asn1-cer | PKI / Certificates | KEEP | BLOCKED | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 731 | asn1-per | PKI / Certificates | KEEP | BLOCKED | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 732 | asn1-oer | PKI / Certificates | KEEP | BLOCKED | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 733 | asn1-xer | PKI / Certificates | KEEP | BLOCKED | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 734 | x509v1 | PKI / Certificates | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 735 | asn1-ber | PKI / Certificates | KEEP | BLOCKED | the Encoding trait is bytes <-> text; der/rasn/cms are typed ASN.1 codecs with no generic byte-level API. Needs a design (owner) |
| 736 | pkcs11 | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 737 | pkcs11-3.0 | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 738 | cng | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 739 | tpm2.0 | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 740 | intel-sgx | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 741 | intel-tdx | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 742 | amd-sev | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 743 | amd-sev-snp | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 744 | arm-trustzone | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 745 | arm-cca | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 746 | apple-secure-enclave | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 747 | nitro-enclaves | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 748 | nvidia-cc | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 754 | opencryptoki | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 755 | softhsm2 | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 756 | capi | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 757 | tpm1.2 | Hardware / HSM / TEE | KEEP-PLATFORM | NONE | no upstream found: no source row |
| 759 | wesolowski-vdf | Verifiable Delay Functions | KEEP | NONE | no upstream found: no source row |
| 760 | pietrzak-vdf | Verifiable Delay Functions | KEEP | NONE | no upstream found: no source row |
| 761 | sloth-vdf | Verifiable Delay Functions | KEEP | NONE | no upstream found: no source row |
| 762 | ibe | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 763 | abe | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 764 | pre | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 765 | functional-encryption | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 766 | witness-encryption | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 767 | chameleon-hash | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 768 | rsa-accumulator | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 769 | bilinear-accumulator | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 770 | vector-commitment | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 771 | psi | Advanced Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 772 | secure-aggregation | Advanced Primitives | KEEP-PROTOCOL | NONE | no upstream found: no source row |
| 773 | oram | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 775 | blakley-ss | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
| 776 | brickell-ss | Advanced Primitives | KEEP | NONE | no upstream found: no source row |
