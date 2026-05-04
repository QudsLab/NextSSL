# Complete algorithm inventory (post-0004 flat hash layout)

This records the named algorithm surface in the NextSSL (8 groups, 249 total algorithm surfaces)

## 1. Encoding algorithms (14)

1. `base16`
2. `base32`
3. `base58`
4. `base64`
5. `base64url`
6. `hex`
7. `ff70`
8. `base58check`
9. `base62`
10. `base85`
11. `bech32`
12. `pem`
13. `crc32`
14. `crc64`

Notes:

- `base16` and `hex` exist as separate named modules/surfaces in the tree even though they are the same radix family.
- `crc32` and `crc64` sit in the encoding surface of `src/root/modern/root_modern.h`, but they are checksum helpers rather than text encodings.

### 2. Hash / KDF-hash algorithms (59)

1. `blake2b`
2. `blake2s`
3. `blake3`
4. `sha224`
5. `sha256`
6. `sha384`
7. `sha512`
8. `sha512-224`
9. `sha512-256`
10. `sm3`
11. `has160`
12. `md2`
13. `md4`
14. `md5`
15. `nt`
16. `ripemd128`
17. `ripemd160`
18. `ripemd256`
19. `ripemd320`
20. `sha0`
21. `sha1`
22. `tiger`
23. `whirlpool`
24. `argon2d`
25. `argon2i`
26. `argon2id`
27. `bcrypt`
28. `catena`
29. `lyra2`
30. `scrypt`
31. `yescrypt`
32. `balloon`
33. `pomelo`
34. `makwa`
35. `keccak256`
36. `sha3-224`
37. `sha3-256`
38. `sha3-384`
39. `sha3-512`
40. `shake`
41. `shake128`
42. `shake256`
43. `cshake`
44. `kmac`
45. `kmac128`
46. `kmac256`
47. `parallelhash`
48. `tuplehash`
49. `skein256`
50. `skein512`
51. `skein1024`
52. **[NEW]** `kmacxof128` — KMAC128 in XOF mode
53. **[NEW]** `kmacxof256` — KMAC256 in XOF mode
54. **[NEW]** `kangarootwelve` — KangarooTwelve tree hash / XOF
55. **[NEW]** `marsupilami14` — MarsupilamiFourteen tree hash / XOF
56. **[NEW]** `parallelhash128` — ParallelHash with 128-bit security strength
57. **[NEW]** `parallelhash256` — ParallelHash with 256-bit security strength
58. **[NEW]** `tuplehash128` — TupleHash with 128-bit security strength
59. **[NEW]** `tuplehash256` — TupleHash with 256-bit security strength

- Plan decision: keep the concrete algorithm count as the source-of-truth inventory count; do not count family selector names as additional algorithms unless an explicit variant surface is listed.

**Hash alias note:**

- `nthash` → `nt`
- `sha512/224` → `sha512-224`
- `sha512/256` → `sha512-256`

### 3. Modern algorithms (83)

1. `aes-cbc`
2. `aes-gcm`
3. `chacha20`
4. `hmac`
5. `poly1305`
6. `hkdf`
7. `pbkdf2`
8. `ed25519`
9. `x25519`
10. `p-256`
11. `p-384`
12. `p-521`
13. `aes-ecb`
14. `aes-ctr`
15. `aes-cfb`
16. `aes-ofb`
17. `aes-xts`
18. `aes-fpe` (FF1)
19. `aes-kw`
20. `3des-cbc`
21. `aes-ccm`
22. `aes-eax`
23. `aes-gcm-siv`
24. `aes-ocb`
25. `aes-siv`
26. `chacha20-poly1305`
27. `aes-cmac`
28. `siphash`
29. `ed448` (conditional)
30. `x448` / `curve448` (conditional)
31. `rsa`
32. `sm2` (conditional)
33. **[NEW]** `aes-cbc-cs` — AES-CBC with ciphertext stealing (CS1/CS2/CS3 variants, SP 800-38A)
34. **[NEW]** `aes-fpe-ff3` — AES Format-Preserving Encryption FF3-1 mode (SP 800-38G)
35. **[NEW]** `aes-gmac` — GCM with empty plaintext; produces auth tag only (SP 800-38D)
36. **[NEW]** `aes-kwp` — AES Key Wrap with Padding (SP 800-38F)
37. **[NEW]** `aes-xpn` — AES-GCM Extended Packet Numbering for MACsec (IEEE 802.1AEbw)
38. **[NEW]** `dsa` — Classical Digital Signature Algorithm (FIPS 186-4)
39. **[NEW]** `det-ecdsa` — Deterministic ECDSA per RFC 6979 (FIPS 186-5)
40. **[NEW]** `kda-onestep` — One-Step Key Derivation (SP 800-56Cr1/2)
41. **[NEW]** `kda-twostep` — Two-Step Key Derivation (SP 800-56Cr1/2)
42. **[NEW]** `kdf-sp800-108` — Counter/Feedback/Pipeline KDF (SP 800-108r1)
43. **[NEW]** `kdf-tls12` — TLS 1.2 PRF key derivation (RFC 7627)
44. **[NEW]** `kdf-tls13` — TLS 1.3 HKDF-based key schedule (RFC 8446)
45. **[NEW]** `kdf-ssh` — SSH key derivation (RFC 4253)
46. **[NEW]** `kdf-ike` — IKEv1/IKEv2 key derivation (RFC 7296)
47. **[NEW]** `kdf-srtp` — SRTP key derivation (RFC 3711)
48. **[NEW]** `kdf-ansi-x963` — ANSI X9.63 key derivation (ANSI X9.63)
49. **[NEW]** `aes-pmac` — Parallelizable AES-based message authentication code
50. **[NEW]** `xcbc-mac` — AES-XCBC-MAC legacy MAC construction
51. **[NEW]** `vmac` — High-speed universal-hash message authentication code
52. **[NEW]** `umac` — Universal-hash message authentication code
53. **[NEW]** `dh` — Finite-field Diffie-Hellman key exchange
54. **[NEW]** `ecdh` — Elliptic-curve Diffie-Hellman key exchange
55. **[NEW]** `ecmqv` — Elliptic-curve MQV authenticated key agreement
56. **[NEW]** `x3dh` — Extended Triple Diffie-Hellman messaging key agreement
57. **[NEW]** `hpke` — Hybrid Public Key Encryption (RFC 9180)
58. **[NEW]** `ecies` — Elliptic Curve Integrated Encryption Scheme
59. **[NEW]** `ecdsa` — Standard Elliptic Curve Digital Signature Algorithm
60. **[NEW]** `rsa-pss` — RSA Probabilistic Signature Scheme
61. **[NEW]** `rsa-pkcs1v15` — RSA PKCS #1 v1.5 signature / encryption surface
62. **[NEW]** `ecdsa-recoverable` — Recoverable ECDSA signatures used in secp256k1 ecosystems
63. **[NEW]** `sr25519` — Schnorrkel / Ristretto255 signature surface
64. **[NEW]** `secp256k1` — Koblitz curve used in Bitcoin and related systems
65. **[NEW]** `concat-kdf` — Concatenation KDF used by NIST / JOSE / ECIES profiles
66. **[NEW]** `x942-kdf` — ANSI X9.42 KDF used in CMS / PKCS ecosystems
67. **[NEW]** `noise-kdf` — Noise Protocol Framework key derivation surface
68. **[NEW]** `bip32-kdf` — BIP32 hierarchical deterministic wallet key derivation
69. **[NEW]** `slip10` — SLIP-0010 deterministic key hierarchy derivation
70. **[NEW]** `sskdf` — Single-step KDF from SP 800-56C
71. **[NEW]** `hkdf-expand-label` — TLS 1.3 labeled HKDF expansion helper
72. **[NEW]** `xchacha20` — Extended-nonce ChaCha20 stream cipher
73. **[NEW]** `salsa20` — Salsa20 stream cipher
74. **[NEW]** `xsalsa20` — Extended-nonce Salsa20 stream cipher
75. **[NEW]** `hc128` — HC-128 stream cipher
76. **[NEW]** `hc256` — HC-256 stream cipher
77. **[NEW]** `rabbit` — Rabbit stream cipher
78. **[NEW]** `sosemanuk` — SOSEMANUK stream cipher
79. **[NEW]** `xchacha20-poly1305` — Extended-nonce ChaCha20-Poly1305 AEAD
80. **[NEW]** `aegis128l` — AEGIS-128L authenticated encryption
81. **[NEW]** `aegis256` — AEGIS-256 authenticated encryption
82. **[NEW]** `deoxys-ii` — Misuse-resistant authenticated encryption
83. **[NEW]** `isap` — Lightweight side-channel-resistant authenticated encryption

### 4. PQC algorithms (41)

1. `ml-kem-512`
2. `ml-kem-768`
3. `ml-kem-1024`
4. `ml-dsa-44`
5. `ml-dsa-65`
6. `ml-dsa-87`
7. `falcon-512`
8. `falcon-1024`
9. `falcon-padded-512`
10. `falcon-padded-1024`
11. `hqc-128`
12. `hqc-192`
13. `hqc-256`
14. `mceliece-348864`
15. `mceliece-348864f`
16. `mceliece-460896`
17. `mceliece-460896f`
18. `mceliece-6688128`
19. `mceliece-6688128f`
20. `mceliece-6960119`
21. `mceliece-6960119f`
22. `mceliece-8192128`
23. `mceliece-8192128f`
24. `sphincs-sha2-128f`
25. `sphincs-sha2-128s`
26. `sphincs-sha2-192f`
27. `sphincs-sha2-192s`
28. `sphincs-sha2-256f`
29. `sphincs-sha2-256s`
30. `sphincs-shake-128f`
31. `sphincs-shake-128s`
32. `sphincs-shake-192f`
33. `sphincs-shake-192s`
34. `sphincs-shake-256f`
35. `sphincs-shake-256s`
36. **[NEW]** `bike-1` — BIKE level-1 code-based KEM
37. **[NEW]** `bike-3` — BIKE level-3 code-based KEM
38. **[NEW]** `classic-mceliece` — Classic McEliece family alias surface
39. **[NEW]** `ntru` — NTRU lattice-based KEM / encryption family
40. **[NEW]** `ntruprime` — NTRU Prime lattice-based KEM family
41. **[NEW]** `sntrup761` — Streamlined NTRU Prime 761 KEM

## **[NEW]** 5. Threshold Cryptography (36)

> Threshold cryptography enables secure multi-party computation of cryptographic operations. A secret key is split into shares distributed among parties; a threshold number of shares must collaborate to perform signing or decryption. This enhances security by eliminating single points of failure and enabling distributed trust.

1. **[NEW]** `frost` (Threshold Schnorr Sign)
2. **[NEW]** `tbla` (Threshold BLS Sign)
3. **[NEW]** `gargos` (Threshold Schnorr Sign)
4. **[NEW]** `tecla` (2-party Threshold ECDSA)
5. **[NEW]** `the-clash` (n-party Threshold ECDSA)
6. **[NEW]** `classic-schnorr` (Threshold Schnorr Sign)
7. **[NEW]** `bam` (2-party ECDSA)
8. **[NEW]** `ccgmp` (n-party ECDSA)
9. **[NEW]** `haystack` (Threshold HBS)
10. **[NEW]** `mithril` (Threshold ML-DSA)
11. **[NEW]** `quorus` (Threshold ML-DSA)
12. **[NEW]** `redeta` (Threshold ECDLP-based Signatures)
13. **[NEW]** `splitkey` (Server-assisted threshold signatures and PKE)
14. **[NEW]** `minimpc` (Threshold AES+SHA+MAC and gadgets)
15. **[NEW]** `maestro` (T-AES, T-SHA, T-MAC and gadgets)
16. **[NEW]** `amber` (Threshold Lattice-based KEM)
17. **[NEW]** `hermine` (Threshold Sign [Lattice-based])
18. **[NEW]** `least` (Threshold Sign [code-based group-actions])
19. **[NEW]** `tanuki` (Threshold Lattice-based Signature)
20. **[NEW]** `vinaigrette` (Threshold UOV+MAYO Signatures)
21. **[NEW]** `pantheria` (RLWE-based FHE and Threshold FHE)
22. **[NEW]** `zama-tfhe` (TFHE, Threshold FHE)
23. **[NEW]** `zama-zhenith` (ZKP)
24. **[NEW]** `piver` (Verifiable Secret Sharing)
25. **[NEW]** `schmivitz` (VOLEith-based ZKPoK)
26. **[NEW]** `smallwood` (Hash-based ZKPoK)
27. **[NEW]** `shamir` (Shamir Secret Sharing)
28. **[NEW]** `feldman-vss` (Feldman Verifiable Secret Sharing)
29. **[NEW]** `pedersen-vss` (Pedersen Verifiable Secret Sharing)
30. **[NEW]** `dkg` (Distributed Key Generation)
31. **[NEW]** `pvss` (Publicly Verifiable Secret Sharing)
32. **[NEW]** `ot` (Oblivious Transfer)
33. **[NEW]** `vole` (Vector Oblivious Linear Evaluation)
34. **[NEW]** `beaver` (Beaver triples for MPC)
35. **[NEW]** `mpc-ecdsa` (Generic MPC ECDSA signing surface)
36. **[NEW]** `mpc-schnorr` (Generic MPC Schnorr signing surface)

## **[NEW]** 6. Ascon — Lightweight Authenticated Cryptography (7)

> SP 800-232 (2024). Ascon is NIST's selected lightweight crypto standard designed for constrained devices (IoT, embedded). Provides AEAD, hashing, and XOF in a single Keccak-like permutation family.

1. **[NEW]** `ascon-aead128` — authenticated encryption with associated data (128-bit key)
2. **[NEW]** `ascon-hash256` — 256-bit hash output
3. **[NEW]** `ascon-xof128` — extendable output function (arbitrary length)
4. **[NEW]** `ascon-cxof128` — customizable XOF (domain-separated variant of xof128)
5. **[NEW]** `ascon-mac` — Ascon message authentication code surface
6. **[NEW]** `ascon-prf` — Ascon pseudorandom function surface
7. **[NEW]** `ascon-80pq` — historical Ascon AEAD variant with 80-bit post-quantum security target

## **[NEW]** 7. DRBG / Randomness Infrastructure (7)

> SP 800-90A. DRBGs produce cryptographically secure pseudo-random output from a seed. Required by FIPS for key generation. Three mechanisms differ in their internal primitive (block cipher, hash, or HMAC).

1. **[NEW]** `ctr-drbg` — AES-256-CTR based DRBG (most common in hardware/HSM contexts)
2. **[NEW]** `hash-drbg` — SHA-based DRBG
3. **[NEW]** `hmac-drbg` — HMAC-based DRBG (default in many TLS stacks)
4. **[NEW]** `csprng-system` — OS-backed cryptographically secure RNG abstraction
5. **[NEW]** `trng` — Hardware true-random entropy source abstraction
6. **[NEW]** `entropy-pool` — Entropy accumulation and conditioning surface
7. **[NEW]** `reseed-scheduler` — DRBG reseed policy / scheduling surface

## **[NEW]** 8. Stateful Hash-Based Signatures (2)

> SP 800-208 / RFC 8391. Stateful signature schemes based on one-time hash functions. Security depends only on hash security (quantum-safe). Require careful key-state management — signing the same state twice is catastrophic.

1. **[NEW]** `lms` — Leighton-Micali Signatures (SP 800-208); NIST approved
2. **[NEW]** `xmss` — eXtended Merkle Signature Scheme (RFC 8391); NIST approved

## **[NEW]** Total is `249`

**Breakdown**
    - Encoding: `14`
    - Hash / KDF-hash: `59`
    - Modern: `83`
    - PQC: `41`
    - Threshold: `36`
    - Ascon: `7`
    - DRBG / randomness: `7`
    - Stateful hash-based signatures: `2`

I already updated the header to `249 total algorithm surfaces`, and I verified it from the numbered entries.

## Inventory note

Items marked **[NEW]** are planned algorithm surfaces to add or expose. The marker does not mean the implementation already exists in the tree.
