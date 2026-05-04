# Complete algorithm inventory (post-0004 flat hash layout)

This records the named algorithm surface in the NextSSL (8 groups, 132 total algorithms)

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

### 2. Hash / KDF-hash algorithms (51)

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

- Plan decision: keep the 51 concrete algorithm count as the source-of-truth inventory count; do not count the family selector name as an additional algorithm

**Hash alias note:**

- `nthash` → `nt`
- `sha512/224` → `sha512-224`
- `sha512/256` → `sha512-256`

### 3. Modern algorithms (48)

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

### 4. PQC algorithms (35)

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

##  **[NEW]** 5. Threshold Cryptography

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

## **[NEW]** 6. Ascon — Lightweight Authenticated Cryptography (4)

> SP 800-232 (2024). Ascon is NIST's selected lightweight crypto standard designed for constrained devices (IoT, embedded). Provides AEAD, hashing, and XOF in a single Keccak-like permutation family.

1. **[NEW]** `ascon-aead128` — authenticated encryption with associated data (128-bit key)
2. **[NEW]** `ascon-hash256` — 256-bit hash output
3. **[NEW]** `ascon-xof128` — extendable output function (arbitrary length)
4. **[NEW]** `ascon-cxof128` — customizable XOF (domain-separated variant of xof128)

## **[NEW]** 7. DRBG — Deterministic Random Bit Generators (3)

> SP 800-90A. DRBGs produce cryptographically secure pseudo-random output from a seed. Required by FIPS for key generation. Three mechanisms differ in their internal primitive (block cipher, hash, or HMAC).

1. **[NEW]** `ctr-drbg` — AES-256-CTR based DRBG (most common in hardware/HSM contexts)
2. **[NEW]** `hash-drbg` — SHA-based DRBG
3. **[NEW]** `hmac-drbg` — HMAC-based DRBG (default in many TLS stacks)

## **[NEW]** 8. Stateful Hash-Based Signatures (2)

> SP 800-208 / RFC 8391. Stateful signature schemes based on one-time hash functions. Security depends only on hash security (quantum-safe). Require careful key-state management — signing the same state twice is catastrophic.

1. **[NEW]** `lms` — Leighton-Micali Signatures (SP 800-208); NIST approved
2. **[NEW]** `xmss` — eXtended Merkle Signature Scheme (RFC 8391); NIST approved
