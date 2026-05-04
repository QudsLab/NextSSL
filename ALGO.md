# Complete algorithm inventory (post-0004 flat hash layout)

This records the named algorithm surface in the NextSSL (8 groups, 249 total algorithm surfaces)

## 1. Encoding algorithms (14)

1. ![base16](https://img.shields.io/badge/base16-encoding-2f7d4f) `base16`
2. ![base32](https://img.shields.io/badge/base32-encoding-2f7d4f) `base32`
3. ![base58](https://img.shields.io/badge/base58-encoding-2f7d4f) `base58`
4. ![base64](https://img.shields.io/badge/base64-encoding-2f7d4f) `base64`
5. ![base64url](https://img.shields.io/badge/base64url-encoding-2f7d4f) `base64url`
6. ![hex](https://img.shields.io/badge/hex-encoding-2f7d4f) `hex`
7. ![ff70](https://img.shields.io/badge/ff70-encoding-2f7d4f) `ff70`
8. ![base58check](https://img.shields.io/badge/base58check-encoding-2f7d4f) `base58check`
9. ![base62](https://img.shields.io/badge/base62-encoding-2f7d4f) `base62`
10. ![base85](https://img.shields.io/badge/base85-encoding-2f7d4f) `base85`
11. ![bech32](https://img.shields.io/badge/bech32-encoding-2f7d4f) `bech32`
12. ![pem](https://img.shields.io/badge/pem-encoding-2f7d4f) `pem`
13. ![crc32](https://img.shields.io/badge/crc32-encoding-2f7d4f) `crc32`
14. ![crc64](https://img.shields.io/badge/crc64-encoding-2f7d4f) `crc64`

Notes:

- `base16` and `hex` exist as separate named modules/surfaces in the tree even though they are the same radix family.
- `crc32` and `crc64` sit in the encoding surface of `src/root/modern/root_modern.h`, but they are checksum helpers rather than text encodings.

### 2. Hash / KDF-hash algorithms (59)

1. ![blake2b](https://img.shields.io/badge/blake2b-hash-6d5796) `blake2b`
2. ![blake2s](https://img.shields.io/badge/blake2s-hash-6d5796) `blake2s`
3. ![blake3](https://img.shields.io/badge/blake3-hash-6d5796) `blake3`
4. ![sha224](https://img.shields.io/badge/sha224-hash-6d5796) `sha224`
5. ![sha256](https://img.shields.io/badge/sha256-hash-6d5796) `sha256`
6. ![sha384](https://img.shields.io/badge/sha384-hash-6d5796) `sha384`
7. ![sha512](https://img.shields.io/badge/sha512-hash-6d5796) `sha512`
8. ![sha512-224](https://img.shields.io/badge/sha512--224-hash-6d5796) `sha512-224`
9. ![sha512-256](https://img.shields.io/badge/sha512--256-hash-6d5796) `sha512-256`
10. ![sm3](https://img.shields.io/badge/sm3-hash-6d5796) `sm3`
11. ![has160](https://img.shields.io/badge/has160-hash-6d5796) `has160`
12. ![md2](https://img.shields.io/badge/md2-hash-6d5796) `md2`
13. ![md4](https://img.shields.io/badge/md4-hash-6d5796) `md4`
14. ![md5](https://img.shields.io/badge/md5-hash-6d5796) `md5`
15. ![nt](https://img.shields.io/badge/nt-hash-6d5796) `nt`
16. ![ripemd128](https://img.shields.io/badge/ripemd128-hash-6d5796) `ripemd128`
17. ![ripemd160](https://img.shields.io/badge/ripemd160-hash-6d5796) `ripemd160`
18. ![ripemd256](https://img.shields.io/badge/ripemd256-hash-6d5796) `ripemd256`
19. ![ripemd320](https://img.shields.io/badge/ripemd320-hash-6d5796) `ripemd320`
20. ![sha0](https://img.shields.io/badge/sha0-hash-6d5796) `sha0`
21. ![sha1](https://img.shields.io/badge/sha1-hash-6d5796) `sha1`
22. ![tiger](https://img.shields.io/badge/tiger-hash-6d5796) `tiger`
23. ![whirlpool](https://img.shields.io/badge/whirlpool-hash-6d5796) `whirlpool`
24. ![argon2d](https://img.shields.io/badge/argon2d-hash-6d5796) `argon2d`
25. ![argon2i](https://img.shields.io/badge/argon2i-hash-6d5796) `argon2i`
26. ![argon2id](https://img.shields.io/badge/argon2id-hash-6d5796) `argon2id`
27. ![bcrypt](https://img.shields.io/badge/bcrypt-hash-6d5796) `bcrypt`
28. ![catena](https://img.shields.io/badge/catena-hash-6d5796) `catena`
29. ![lyra2](https://img.shields.io/badge/lyra2-hash-6d5796) `lyra2`
30. ![scrypt](https://img.shields.io/badge/scrypt-hash-6d5796) `scrypt`
31. ![yescrypt](https://img.shields.io/badge/yescrypt-hash-6d5796) `yescrypt`
32. ![balloon](https://img.shields.io/badge/balloon-hash-6d5796) `balloon`
33. ![pomelo](https://img.shields.io/badge/pomelo-hash-6d5796) `pomelo`
34. ![makwa](https://img.shields.io/badge/makwa-hash-6d5796) `makwa`
35. ![keccak256](https://img.shields.io/badge/keccak256-hash-6d5796) `keccak256`
36. ![sha3-224](https://img.shields.io/badge/sha3--224-hash-6d5796) `sha3-224`
37. ![sha3-256](https://img.shields.io/badge/sha3--256-hash-6d5796) `sha3-256`
38. ![sha3-384](https://img.shields.io/badge/sha3--384-hash-6d5796) `sha3-384`
39. ![sha3-512](https://img.shields.io/badge/sha3--512-hash-6d5796) `sha3-512`
40. ![shake](https://img.shields.io/badge/shake-hash-6d5796) `shake`
41. ![shake128](https://img.shields.io/badge/shake128-hash-6d5796) `shake128`
42. ![shake256](https://img.shields.io/badge/shake256-hash-6d5796) `shake256`
43. ![cshake](https://img.shields.io/badge/cshake-hash-6d5796) `cshake`
44. ![kmac](https://img.shields.io/badge/kmac-hash-6d5796) `kmac`
45. ![kmac128](https://img.shields.io/badge/kmac128-hash-6d5796) `kmac128`
46. ![kmac256](https://img.shields.io/badge/kmac256-hash-6d5796) `kmac256`
47. ![parallelhash](https://img.shields.io/badge/parallelhash-hash-6d5796) `parallelhash`
48. ![tuplehash](https://img.shields.io/badge/tuplehash-hash-6d5796) `tuplehash`
49. ![skein256](https://img.shields.io/badge/skein256-hash-6d5796) `skein256`
50. ![skein512](https://img.shields.io/badge/skein512-hash-6d5796) `skein512`
51. ![skein1024](https://img.shields.io/badge/skein1024-hash-6d5796) `skein1024`
52. ![kmacxof128](https://img.shields.io/badge/kmacxof128-hash-6d5796) **[NEW]** `kmacxof128` â€” KMAC128 in XOF mode
53. ![kmacxof256](https://img.shields.io/badge/kmacxof256-hash-6d5796) **[NEW]** `kmacxof256` â€” KMAC256 in XOF mode
54. ![kangarootwelve](https://img.shields.io/badge/kangarootwelve-hash-6d5796) **[NEW]** `kangarootwelve` â€” KangarooTwelve tree hash / XOF
55. ![marsupilami14](https://img.shields.io/badge/marsupilami14-hash-6d5796) **[NEW]** `marsupilami14` â€” MarsupilamiFourteen tree hash / XOF
56. ![parallelhash128](https://img.shields.io/badge/parallelhash128-hash-6d5796) **[NEW]** `parallelhash128` â€” ParallelHash with 128-bit security strength
57. ![parallelhash256](https://img.shields.io/badge/parallelhash256-hash-6d5796) **[NEW]** `parallelhash256` â€” ParallelHash with 256-bit security strength
58. ![tuplehash128](https://img.shields.io/badge/tuplehash128-hash-6d5796) **[NEW]** `tuplehash128` â€” TupleHash with 128-bit security strength
59. ![tuplehash256](https://img.shields.io/badge/tuplehash256-hash-6d5796) **[NEW]** `tuplehash256` â€” TupleHash with 256-bit security strength

- Plan decision: keep the concrete algorithm count as the source-of-truth inventory count; do not count family selector names as additional algorithms unless an explicit variant surface is listed.

**Hash alias note:**

- `nthash` â†’ `nt`
- `sha512/224` â†’ `sha512-224`
- `sha512/256` â†’ `sha512-256`

### 3. Modern algorithms (83)

1. ![aes-cbc](https://img.shields.io/badge/aes--cbc-modern-1f6f9f) `aes-cbc`
2. ![aes-gcm](https://img.shields.io/badge/aes--gcm-modern-1f6f9f) `aes-gcm`
3. ![chacha20](https://img.shields.io/badge/chacha20-modern-1f6f9f) `chacha20`
4. ![hmac](https://img.shields.io/badge/hmac-modern-1f6f9f) `hmac`
5. ![poly1305](https://img.shields.io/badge/poly1305-modern-1f6f9f) `poly1305`
6. ![hkdf](https://img.shields.io/badge/hkdf-modern-1f6f9f) `hkdf`
7. ![pbkdf2](https://img.shields.io/badge/pbkdf2-modern-1f6f9f) `pbkdf2`
8. ![ed25519](https://img.shields.io/badge/ed25519-modern-1f6f9f) `ed25519`
9. ![x25519](https://img.shields.io/badge/x25519-modern-1f6f9f) `x25519`
10. ![p-256](https://img.shields.io/badge/p--256-modern-1f6f9f) `p-256`
11. ![p-384](https://img.shields.io/badge/p--384-modern-1f6f9f) `p-384`
12. ![p-521](https://img.shields.io/badge/p--521-modern-1f6f9f) `p-521`
13. ![aes-ecb](https://img.shields.io/badge/aes--ecb-modern-1f6f9f) `aes-ecb`
14. ![aes-ctr](https://img.shields.io/badge/aes--ctr-modern-1f6f9f) `aes-ctr`
15. ![aes-cfb](https://img.shields.io/badge/aes--cfb-modern-1f6f9f) `aes-cfb`
16. ![aes-ofb](https://img.shields.io/badge/aes--ofb-modern-1f6f9f) `aes-ofb`
17. ![aes-xts](https://img.shields.io/badge/aes--xts-modern-1f6f9f) `aes-xts`
18. ![aes-fpe](https://img.shields.io/badge/aes--fpe-modern-1f6f9f) `aes-fpe` (FF1)
19. ![aes-kw](https://img.shields.io/badge/aes--kw-modern-1f6f9f) `aes-kw`
20. ![3des-cbc](https://img.shields.io/badge/3des--cbc-modern-1f6f9f) `3des-cbc`
21. ![aes-ccm](https://img.shields.io/badge/aes--ccm-modern-1f6f9f) `aes-ccm`
22. ![aes-eax](https://img.shields.io/badge/aes--eax-modern-1f6f9f) `aes-eax`
23. ![aes-gcm-siv](https://img.shields.io/badge/aes--gcm--siv-modern-1f6f9f) `aes-gcm-siv`
24. ![aes-ocb](https://img.shields.io/badge/aes--ocb-modern-1f6f9f) `aes-ocb`
25. ![aes-siv](https://img.shields.io/badge/aes--siv-modern-1f6f9f) `aes-siv`
26. ![chacha20-poly1305](https://img.shields.io/badge/chacha20--poly1305-modern-1f6f9f) `chacha20-poly1305`
27. ![aes-cmac](https://img.shields.io/badge/aes--cmac-modern-1f6f9f) `aes-cmac`
28. ![siphash](https://img.shields.io/badge/siphash-modern-1f6f9f) `siphash`
29. ![ed448](https://img.shields.io/badge/ed448-modern-1f6f9f) `ed448` (conditional)
30. ![x448](https://img.shields.io/badge/x448-modern-1f6f9f) `x448` / `curve448` (conditional)
31. ![rsa](https://img.shields.io/badge/rsa-modern-1f6f9f) `rsa`
32. ![sm2](https://img.shields.io/badge/sm2-modern-1f6f9f) `sm2` (conditional)
33. ![aes-cbc-cs](https://img.shields.io/badge/aes--cbc--cs-modern-1f6f9f) **[NEW]** `aes-cbc-cs` â€” AES-CBC with ciphertext stealing (CS1/CS2/CS3 variants, SP 800-38A)
34. ![aes-fpe-ff3](https://img.shields.io/badge/aes--fpe--ff3-modern-1f6f9f) **[NEW]** `aes-fpe-ff3` â€” AES Format-Preserving Encryption FF3-1 mode (SP 800-38G)
35. ![aes-gmac](https://img.shields.io/badge/aes--gmac-modern-1f6f9f) **[NEW]** `aes-gmac` â€” GCM with empty plaintext; produces auth tag only (SP 800-38D)
36. ![aes-kwp](https://img.shields.io/badge/aes--kwp-modern-1f6f9f) **[NEW]** `aes-kwp` â€” AES Key Wrap with Padding (SP 800-38F)
37. ![aes-xpn](https://img.shields.io/badge/aes--xpn-modern-1f6f9f) **[NEW]** `aes-xpn` â€” AES-GCM Extended Packet Numbering for MACsec (IEEE 802.1AEbw)
38. ![dsa](https://img.shields.io/badge/dsa-modern-1f6f9f) **[NEW]** `dsa` â€” Classical Digital Signature Algorithm (FIPS 186-4)
39. ![det-ecdsa](https://img.shields.io/badge/det--ecdsa-modern-1f6f9f) **[NEW]** `det-ecdsa` â€” Deterministic ECDSA per RFC 6979 (FIPS 186-5)
40. ![kda-onestep](https://img.shields.io/badge/kda--onestep-modern-1f6f9f) **[NEW]** `kda-onestep` â€” One-Step Key Derivation (SP 800-56Cr1/2)
41. ![kda-twostep](https://img.shields.io/badge/kda--twostep-modern-1f6f9f) **[NEW]** `kda-twostep` â€” Two-Step Key Derivation (SP 800-56Cr1/2)
42. ![kdf-sp800-108](https://img.shields.io/badge/kdf--sp800--108-modern-1f6f9f) **[NEW]** `kdf-sp800-108` â€” Counter/Feedback/Pipeline KDF (SP 800-108r1)
43. ![kdf-tls12](https://img.shields.io/badge/kdf--tls12-modern-1f6f9f) **[NEW]** `kdf-tls12` â€” TLS 1.2 PRF key derivation (RFC 7627)
44. ![kdf-tls13](https://img.shields.io/badge/kdf--tls13-modern-1f6f9f) **[NEW]** `kdf-tls13` â€” TLS 1.3 HKDF-based key schedule (RFC 8446)
45. ![kdf-ssh](https://img.shields.io/badge/kdf--ssh-modern-1f6f9f) **[NEW]** `kdf-ssh` â€” SSH key derivation (RFC 4253)
46. ![kdf-ike](https://img.shields.io/badge/kdf--ike-modern-1f6f9f) **[NEW]** `kdf-ike` â€” IKEv1/IKEv2 key derivation (RFC 7296)
47. ![kdf-srtp](https://img.shields.io/badge/kdf--srtp-modern-1f6f9f) **[NEW]** `kdf-srtp` â€” SRTP key derivation (RFC 3711)
48. ![kdf-ansi-x963](https://img.shields.io/badge/kdf--ansi--x963-modern-1f6f9f) **[NEW]** `kdf-ansi-x963` â€” ANSI X9.63 key derivation (ANSI X9.63)
49. ![aes-pmac](https://img.shields.io/badge/aes--pmac-modern-1f6f9f) **[NEW]** `aes-pmac` â€” Parallelizable AES-based message authentication code
50. ![xcbc-mac](https://img.shields.io/badge/xcbc--mac-modern-1f6f9f) **[NEW]** `xcbc-mac` â€” AES-XCBC-MAC legacy MAC construction
51. ![vmac](https://img.shields.io/badge/vmac-modern-1f6f9f) **[NEW]** `vmac` â€” High-speed universal-hash message authentication code
52. ![umac](https://img.shields.io/badge/umac-modern-1f6f9f) **[NEW]** `umac` â€” Universal-hash message authentication code
53. ![dh](https://img.shields.io/badge/dh-modern-1f6f9f) **[NEW]** `dh` â€” Finite-field Diffie-Hellman key exchange
54. ![ecdh](https://img.shields.io/badge/ecdh-modern-1f6f9f) **[NEW]** `ecdh` â€” Elliptic-curve Diffie-Hellman key exchange
55. ![ecmqv](https://img.shields.io/badge/ecmqv-modern-1f6f9f) **[NEW]** `ecmqv` â€” Elliptic-curve MQV authenticated key agreement
56. ![x3dh](https://img.shields.io/badge/x3dh-modern-1f6f9f) **[NEW]** `x3dh` â€” Extended Triple Diffie-Hellman messaging key agreement
57. ![hpke](https://img.shields.io/badge/hpke-modern-1f6f9f) **[NEW]** `hpke` â€” Hybrid Public Key Encryption (RFC 9180)
58. ![ecies](https://img.shields.io/badge/ecies-modern-1f6f9f) **[NEW]** `ecies` â€” Elliptic Curve Integrated Encryption Scheme
59. ![ecdsa](https://img.shields.io/badge/ecdsa-modern-1f6f9f) **[NEW]** `ecdsa` â€” Standard Elliptic Curve Digital Signature Algorithm
60. ![rsa-pss](https://img.shields.io/badge/rsa--pss-modern-1f6f9f) **[NEW]** `rsa-pss` â€” RSA Probabilistic Signature Scheme
61. ![rsa-pkcs1v15](https://img.shields.io/badge/rsa--pkcs1v15-modern-1f6f9f) **[NEW]** `rsa-pkcs1v15` â€” RSA PKCS #1 v1.5 signature / encryption surface
62. ![ecdsa-recoverable](https://img.shields.io/badge/ecdsa--recoverable-modern-1f6f9f) **[NEW]** `ecdsa-recoverable` â€” Recoverable ECDSA signatures used in secp256k1 ecosystems
63. ![sr25519](https://img.shields.io/badge/sr25519-modern-1f6f9f) **[NEW]** `sr25519` â€” Schnorrkel / Ristretto255 signature surface
64. ![secp256k1](https://img.shields.io/badge/secp256k1-modern-1f6f9f) **[NEW]** `secp256k1` â€” Koblitz curve used in Bitcoin and related systems
65. ![concat-kdf](https://img.shields.io/badge/concat--kdf-modern-1f6f9f) **[NEW]** `concat-kdf` â€” Concatenation KDF used by NIST / JOSE / ECIES profiles
66. ![x942-kdf](https://img.shields.io/badge/x942--kdf-modern-1f6f9f) **[NEW]** `x942-kdf` â€” ANSI X9.42 KDF used in CMS / PKCS ecosystems
67. ![noise-kdf](https://img.shields.io/badge/noise--kdf-modern-1f6f9f) **[NEW]** `noise-kdf` â€” Noise Protocol Framework key derivation surface
68. ![bip32-kdf](https://img.shields.io/badge/bip32--kdf-modern-1f6f9f) **[NEW]** `bip32-kdf` â€” BIP32 hierarchical deterministic wallet key derivation
69. ![slip10](https://img.shields.io/badge/slip10-modern-1f6f9f) **[NEW]** `slip10` â€” SLIP-0010 deterministic key hierarchy derivation
70. ![sskdf](https://img.shields.io/badge/sskdf-modern-1f6f9f) **[NEW]** `sskdf` â€” Single-step KDF from SP 800-56C
71. ![hkdf-expand-label](https://img.shields.io/badge/hkdf--expand--label-modern-1f6f9f) **[NEW]** `hkdf-expand-label` â€” TLS 1.3 labeled HKDF expansion helper
72. ![xchacha20](https://img.shields.io/badge/xchacha20-modern-1f6f9f) **[NEW]** `xchacha20` â€” Extended-nonce ChaCha20 stream cipher
73. ![salsa20](https://img.shields.io/badge/salsa20-modern-1f6f9f) **[NEW]** `salsa20` â€” Salsa20 stream cipher
74. ![xsalsa20](https://img.shields.io/badge/xsalsa20-modern-1f6f9f) **[NEW]** `xsalsa20` â€” Extended-nonce Salsa20 stream cipher
75. ![hc128](https://img.shields.io/badge/hc128-modern-1f6f9f) **[NEW]** `hc128` â€” HC-128 stream cipher
76. ![hc256](https://img.shields.io/badge/hc256-modern-1f6f9f) **[NEW]** `hc256` â€” HC-256 stream cipher
77. ![rabbit](https://img.shields.io/badge/rabbit-modern-1f6f9f) **[NEW]** `rabbit` â€” Rabbit stream cipher
78. ![sosemanuk](https://img.shields.io/badge/sosemanuk-modern-1f6f9f) **[NEW]** `sosemanuk` â€” SOSEMANUK stream cipher
79. ![xchacha20-poly1305](https://img.shields.io/badge/xchacha20--poly1305-modern-1f6f9f) **[NEW]** `xchacha20-poly1305` â€” Extended-nonce ChaCha20-Poly1305 AEAD
80. ![aegis128l](https://img.shields.io/badge/aegis128l-modern-1f6f9f) **[NEW]** `aegis128l` â€” AEGIS-128L authenticated encryption
81. ![aegis256](https://img.shields.io/badge/aegis256-modern-1f6f9f) **[NEW]** `aegis256` â€” AEGIS-256 authenticated encryption
82. ![deoxys-ii](https://img.shields.io/badge/deoxys--ii-modern-1f6f9f) **[NEW]** `deoxys-ii` â€” Misuse-resistant authenticated encryption
83. ![isap](https://img.shields.io/badge/isap-modern-1f6f9f) **[NEW]** `isap` â€” Lightweight side-channel-resistant authenticated encryption

### 4. PQC algorithms (41)

1. ![ml-kem-512](https://img.shields.io/badge/ml--kem--512-pqc-8f3f62) `ml-kem-512`
2. ![ml-kem-768](https://img.shields.io/badge/ml--kem--768-pqc-8f3f62) `ml-kem-768`
3. ![ml-kem-1024](https://img.shields.io/badge/ml--kem--1024-pqc-8f3f62) `ml-kem-1024`
4. ![ml-dsa-44](https://img.shields.io/badge/ml--dsa--44-pqc-8f3f62) `ml-dsa-44`
5. ![ml-dsa-65](https://img.shields.io/badge/ml--dsa--65-pqc-8f3f62) `ml-dsa-65`
6. ![ml-dsa-87](https://img.shields.io/badge/ml--dsa--87-pqc-8f3f62) `ml-dsa-87`
7. ![falcon-512](https://img.shields.io/badge/falcon--512-pqc-8f3f62) `falcon-512`
8. ![falcon-1024](https://img.shields.io/badge/falcon--1024-pqc-8f3f62) `falcon-1024`
9. ![falcon-padded-512](https://img.shields.io/badge/falcon--padded--512-pqc-8f3f62) `falcon-padded-512`
10. ![falcon-padded-1024](https://img.shields.io/badge/falcon--padded--1024-pqc-8f3f62) `falcon-padded-1024`
11. ![hqc-128](https://img.shields.io/badge/hqc--128-pqc-8f3f62) `hqc-128`
12. ![hqc-192](https://img.shields.io/badge/hqc--192-pqc-8f3f62) `hqc-192`
13. ![hqc-256](https://img.shields.io/badge/hqc--256-pqc-8f3f62) `hqc-256`
14. ![mceliece-348864](https://img.shields.io/badge/mceliece--348864-pqc-8f3f62) `mceliece-348864`
15. ![mceliece-348864f](https://img.shields.io/badge/mceliece--348864f-pqc-8f3f62) `mceliece-348864f`
16. ![mceliece-460896](https://img.shields.io/badge/mceliece--460896-pqc-8f3f62) `mceliece-460896`
17. ![mceliece-460896f](https://img.shields.io/badge/mceliece--460896f-pqc-8f3f62) `mceliece-460896f`
18. ![mceliece-6688128](https://img.shields.io/badge/mceliece--6688128-pqc-8f3f62) `mceliece-6688128`
19. ![mceliece-6688128f](https://img.shields.io/badge/mceliece--6688128f-pqc-8f3f62) `mceliece-6688128f`
20. ![mceliece-6960119](https://img.shields.io/badge/mceliece--6960119-pqc-8f3f62) `mceliece-6960119`
21. ![mceliece-6960119f](https://img.shields.io/badge/mceliece--6960119f-pqc-8f3f62) `mceliece-6960119f`
22. ![mceliece-8192128](https://img.shields.io/badge/mceliece--8192128-pqc-8f3f62) `mceliece-8192128`
23. ![mceliece-8192128f](https://img.shields.io/badge/mceliece--8192128f-pqc-8f3f62) `mceliece-8192128f`
24. ![sphincs-sha2-128f](https://img.shields.io/badge/sphincs--sha2--128f-pqc-8f3f62) `sphincs-sha2-128f`
25. ![sphincs-sha2-128s](https://img.shields.io/badge/sphincs--sha2--128s-pqc-8f3f62) `sphincs-sha2-128s`
26. ![sphincs-sha2-192f](https://img.shields.io/badge/sphincs--sha2--192f-pqc-8f3f62) `sphincs-sha2-192f`
27. ![sphincs-sha2-192s](https://img.shields.io/badge/sphincs--sha2--192s-pqc-8f3f62) `sphincs-sha2-192s`
28. ![sphincs-sha2-256f](https://img.shields.io/badge/sphincs--sha2--256f-pqc-8f3f62) `sphincs-sha2-256f`
29. ![sphincs-sha2-256s](https://img.shields.io/badge/sphincs--sha2--256s-pqc-8f3f62) `sphincs-sha2-256s`
30. ![sphincs-shake-128f](https://img.shields.io/badge/sphincs--shake--128f-pqc-8f3f62) `sphincs-shake-128f`
31. ![sphincs-shake-128s](https://img.shields.io/badge/sphincs--shake--128s-pqc-8f3f62) `sphincs-shake-128s`
32. ![sphincs-shake-192f](https://img.shields.io/badge/sphincs--shake--192f-pqc-8f3f62) `sphincs-shake-192f`
33. ![sphincs-shake-192s](https://img.shields.io/badge/sphincs--shake--192s-pqc-8f3f62) `sphincs-shake-192s`
34. ![sphincs-shake-256f](https://img.shields.io/badge/sphincs--shake--256f-pqc-8f3f62) `sphincs-shake-256f`
35. ![sphincs-shake-256s](https://img.shields.io/badge/sphincs--shake--256s-pqc-8f3f62) `sphincs-shake-256s`
36. ![bike-1](https://img.shields.io/badge/bike--1-pqc-8f3f62) **[NEW]** `bike-1` â€” BIKE level-1 code-based KEM
37. ![bike-3](https://img.shields.io/badge/bike--3-pqc-8f3f62) **[NEW]** `bike-3` â€” BIKE level-3 code-based KEM
38. ![classic-mceliece](https://img.shields.io/badge/classic--mceliece-pqc-8f3f62) **[NEW]** `classic-mceliece` â€” Classic McEliece family alias surface
39. ![ntru](https://img.shields.io/badge/ntru-pqc-8f3f62) **[NEW]** `ntru` â€” NTRU lattice-based KEM / encryption family
40. ![ntruprime](https://img.shields.io/badge/ntruprime-pqc-8f3f62) **[NEW]** `ntruprime` â€” NTRU Prime lattice-based KEM family
41. ![sntrup761](https://img.shields.io/badge/sntrup761-pqc-8f3f62) **[NEW]** `sntrup761` â€” Streamlined NTRU Prime 761 KEM

## **[NEW]** 5. Threshold Cryptography (36)

> Threshold cryptography enables secure multi-party computation of cryptographic operations. A secret key is split into shares distributed among parties; a threshold number of shares must collaborate to perform signing or decryption. This enhances security by eliminating single points of failure and enabling distributed trust.

1. ![frost](https://img.shields.io/badge/frost-threshold-9a5b1f) **[NEW]** `frost` (Threshold Schnorr Sign)
2. ![tbla](https://img.shields.io/badge/tbla-threshold-9a5b1f) **[NEW]** `tbla` (Threshold BLS Sign)
3. ![gargos](https://img.shields.io/badge/gargos-threshold-9a5b1f) **[NEW]** `gargos` (Threshold Schnorr Sign)
4. ![tecla](https://img.shields.io/badge/tecla-threshold-9a5b1f) **[NEW]** `tecla` (2-party Threshold ECDSA)
5. ![the-clash](https://img.shields.io/badge/the--clash-threshold-9a5b1f) **[NEW]** `the-clash` (n-party Threshold ECDSA)
6. ![classic-schnorr](https://img.shields.io/badge/classic--schnorr-threshold-9a5b1f) **[NEW]** `classic-schnorr` (Threshold Schnorr Sign)
7. ![bam](https://img.shields.io/badge/bam-threshold-9a5b1f) **[NEW]** `bam` (2-party ECDSA)
8. ![ccgmp](https://img.shields.io/badge/ccgmp-threshold-9a5b1f) **[NEW]** `ccgmp` (n-party ECDSA)
9. ![haystack](https://img.shields.io/badge/haystack-threshold-9a5b1f) **[NEW]** `haystack` (Threshold HBS)
10. ![mithril](https://img.shields.io/badge/mithril-threshold-9a5b1f) **[NEW]** `mithril` (Threshold ML-DSA)
11. ![quorus](https://img.shields.io/badge/quorus-threshold-9a5b1f) **[NEW]** `quorus` (Threshold ML-DSA)
12. ![redeta](https://img.shields.io/badge/redeta-threshold-9a5b1f) **[NEW]** `redeta` (Threshold ECDLP-based Signatures)
13. ![splitkey](https://img.shields.io/badge/splitkey-threshold-9a5b1f) **[NEW]** `splitkey` (Server-assisted threshold signatures and PKE)
14. ![minimpc](https://img.shields.io/badge/minimpc-threshold-9a5b1f) **[NEW]** `minimpc` (Threshold AES+SHA+MAC and gadgets)
15. ![maestro](https://img.shields.io/badge/maestro-threshold-9a5b1f) **[NEW]** `maestro` (T-AES, T-SHA, T-MAC and gadgets)
16. ![amber](https://img.shields.io/badge/amber-threshold-9a5b1f) **[NEW]** `amber` (Threshold Lattice-based KEM)
17. ![hermine](https://img.shields.io/badge/hermine-threshold-9a5b1f) **[NEW]** `hermine` (Threshold Sign [Lattice-based])
18. ![least](https://img.shields.io/badge/least-threshold-9a5b1f) **[NEW]** `least` (Threshold Sign [code-based group-actions])
19. ![tanuki](https://img.shields.io/badge/tanuki-threshold-9a5b1f) **[NEW]** `tanuki` (Threshold Lattice-based Signature)
20. ![vinaigrette](https://img.shields.io/badge/vinaigrette-threshold-9a5b1f) **[NEW]** `vinaigrette` (Threshold UOV+MAYO Signatures)
21. ![pantheria](https://img.shields.io/badge/pantheria-threshold-9a5b1f) **[NEW]** `pantheria` (RLWE-based FHE and Threshold FHE)
22. ![zama-tfhe](https://img.shields.io/badge/zama--tfhe-threshold-9a5b1f) **[NEW]** `zama-tfhe` (TFHE, Threshold FHE)
23. ![zama-zhenith](https://img.shields.io/badge/zama--zhenith-threshold-9a5b1f) **[NEW]** `zama-zhenith` (ZKP)
24. ![piver](https://img.shields.io/badge/piver-threshold-9a5b1f) **[NEW]** `piver` (Verifiable Secret Sharing)
25. ![schmivitz](https://img.shields.io/badge/schmivitz-threshold-9a5b1f) **[NEW]** `schmivitz` (VOLEith-based ZKPoK)
26. ![smallwood](https://img.shields.io/badge/smallwood-threshold-9a5b1f) **[NEW]** `smallwood` (Hash-based ZKPoK)
27. ![shamir](https://img.shields.io/badge/shamir-threshold-9a5b1f) **[NEW]** `shamir` (Shamir Secret Sharing)
28. ![feldman-vss](https://img.shields.io/badge/feldman--vss-threshold-9a5b1f) **[NEW]** `feldman-vss` (Feldman Verifiable Secret Sharing)
29. ![pedersen-vss](https://img.shields.io/badge/pedersen--vss-threshold-9a5b1f) **[NEW]** `pedersen-vss` (Pedersen Verifiable Secret Sharing)
30. ![dkg](https://img.shields.io/badge/dkg-threshold-9a5b1f) **[NEW]** `dkg` (Distributed Key Generation)
31. ![pvss](https://img.shields.io/badge/pvss-threshold-9a5b1f) **[NEW]** `pvss` (Publicly Verifiable Secret Sharing)
32. ![ot](https://img.shields.io/badge/ot-threshold-9a5b1f) **[NEW]** `ot` (Oblivious Transfer)
33. ![vole](https://img.shields.io/badge/vole-threshold-9a5b1f) **[NEW]** `vole` (Vector Oblivious Linear Evaluation)
34. ![beaver](https://img.shields.io/badge/beaver-threshold-9a5b1f) **[NEW]** `beaver` (Beaver triples for MPC)
35. ![mpc-ecdsa](https://img.shields.io/badge/mpc--ecdsa-threshold-9a5b1f) **[NEW]** `mpc-ecdsa` (Generic MPC ECDSA signing surface)
36. ![mpc-schnorr](https://img.shields.io/badge/mpc--schnorr-threshold-9a5b1f) **[NEW]** `mpc-schnorr` (Generic MPC Schnorr signing surface)

## **[NEW]** 6. Ascon â€” Lightweight Authenticated Cryptography (7)

> SP 800-232 (2024). Ascon is NIST's selected lightweight crypto standard designed for constrained devices (IoT, embedded). Provides AEAD, hashing, and XOF in a single Keccak-like permutation family.

1. ![ascon-aead128](https://img.shields.io/badge/ascon--aead128-ascon-2f6f9f) **[NEW]** `ascon-aead128` â€” authenticated encryption with associated data (128-bit key)
2. ![ascon-hash256](https://img.shields.io/badge/ascon--hash256-ascon-2f6f9f) **[NEW]** `ascon-hash256` â€” 256-bit hash output
3. ![ascon-xof128](https://img.shields.io/badge/ascon--xof128-ascon-2f6f9f) **[NEW]** `ascon-xof128` â€” extendable output function (arbitrary length)
4. ![ascon-cxof128](https://img.shields.io/badge/ascon--cxof128-ascon-2f6f9f) **[NEW]** `ascon-cxof128` â€” customizable XOF (domain-separated variant of xof128)
5. ![ascon-mac](https://img.shields.io/badge/ascon--mac-ascon-2f6f9f) **[NEW]** `ascon-mac` â€” Ascon message authentication code surface
6. ![ascon-prf](https://img.shields.io/badge/ascon--prf-ascon-2f6f9f) **[NEW]** `ascon-prf` â€” Ascon pseudorandom function surface
7. ![ascon-80pq](https://img.shields.io/badge/ascon--80pq-ascon-2f6f9f) **[NEW]** `ascon-80pq` â€” historical Ascon AEAD variant with 80-bit post-quantum security target

## **[NEW]** 7. DRBG / Randomness Infrastructure (7)

> SP 800-90A. DRBGs produce cryptographically secure pseudo-random output from a seed. Required by FIPS for key generation. Three mechanisms differ in their internal primitive (block cipher, hash, or HMAC).

1. ![ctr-drbg](https://img.shields.io/badge/ctr--drbg-rng-856404) **[NEW]** `ctr-drbg` â€” AES-256-CTR based DRBG (most common in hardware/HSM contexts)
2. ![hash-drbg](https://img.shields.io/badge/hash--drbg-rng-856404) **[NEW]** `hash-drbg` â€” SHA-based DRBG
3. ![hmac-drbg](https://img.shields.io/badge/hmac--drbg-rng-856404) **[NEW]** `hmac-drbg` â€” HMAC-based DRBG (default in many TLS stacks)
4. ![csprng-system](https://img.shields.io/badge/csprng--system-rng-856404) **[NEW]** `csprng-system` â€” OS-backed cryptographically secure RNG abstraction
5. ![trng](https://img.shields.io/badge/trng-rng-856404) **[NEW]** `trng` â€” Hardware true-random entropy source abstraction
6. ![entropy-pool](https://img.shields.io/badge/entropy--pool-rng-856404) **[NEW]** `entropy-pool` â€” Entropy accumulation and conditioning surface
7. ![reseed-scheduler](https://img.shields.io/badge/reseed--scheduler-rng-856404) **[NEW]** `reseed-scheduler` â€” DRBG reseed policy / scheduling surface

## **[NEW]** 8. Stateful Hash-Based Signatures (2)

> SP 800-208 / RFC 8391. Stateful signature schemes based on one-time hash functions. Security depends only on hash security (quantum-safe). Require careful key-state management â€” signing the same state twice is catastrophic.

1. ![lms](https://img.shields.io/badge/lms-hbs-4b5563) **[NEW]** `lms` â€” Leighton-Micali Signatures (SP 800-208); NIST approved
2. ![xmss](https://img.shields.io/badge/xmss-hbs-4b5563) **[NEW]** `xmss` â€” eXtended Merkle Signature Scheme (RFC 8391); NIST approved

## Inventory note

Items marked **[NEW]** are planned algorithm surfaces to add or expose. The marker does not mean the implementation already exists in the tree.
