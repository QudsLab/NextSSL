# Complete algorithm inventory (post-40007.1 revalidation)

This records the named algorithm surface in the NextSSL

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

### 2. Hash / KDF-hash algorithms (45)

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
22. `whirlpool`
23. `argon2d`
24. `argon2i`
25. `argon2id`
26. `bcrypt`
27. `catena`
28. `lyra2`
29. `scrypt`
30. `yescrypt`
31. `balloon`
32. `pomelo`
33. `makwa`
34. `keccak256`
35. `sha3-224`
36. `sha3-256`
37. `sha3-384`
38. `sha3-512`
39. `shake128`
40. `shake256`
41. `skein256`
42. `skein512`
43. `skein1024`
44. `kmac128`
45. `kmac256`

- Plan decision: keep the 45 concrete algorithm count as the source-of-truth inventory count; do not count the family selector name as an additional algorithm

**Hash alias note:**

- `nthash` → `nt`
- `sha512/224` → `sha512-224`
- `sha512/256` → `sha512-256`

### 3. Modern algorithms (32)

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

## 5. Threshold Cryptography (NIST Standards in Development)

**Note:** NIST has not yet finalized specific threshold cryptography standards. Current work is in the "call for proposals" phase (NIST IR 8214C, January 2026). However, threshold schemes can be applied to the following NIST-approved primitives:

1. `threshold-ecdsa` (FIPS 186-4)
2. `threshold-schnorr` (FIPS 186-5)
3. `threshold-ecdh` (SP 800-56A)
4. `threshold-rsa` (SP 800-56B)
5. `threshold-aes` (FIPS 197)
6. `threshold-ed25519` (draft)
7. `threshold-ed448` (draft)

**Key NIST Publications:**

- **NIST IR 8214C** (2026): First Call for Multi-Party Threshold Schemes
- **NIST IR 8214A** (2020): Roadmap Toward Criteria for Threshold Schemes
- **NIST IR 8214** (2019): Challenges and Opportunities in Standardization

### NIST IR 8214C Submissions (First Call - 2026)

1. `frost` (Threshold Schnorr Sign)
2. `tbla` (Threshold BLS Sign)
3. `gargos` (Threshold Schnorr Sign)
4. `tecla` (2-party Threshold ECDSA)
5. `the-clash` (n-party Threshold ECDSA)
6. `classic-schnorr` (Threshold Schnorr Sign)
7. `bam` (2-party ECDSA)
8. `ccgmp` (n-party ECDSA)
9. `haystack` (Threshold HBS)
10. `mithril` (Threshold ML-DSA)
11. `quorus` (Threshold ML-DSA)
12. `redeta` (Threshold ECDLP-based Signatures)
13. `splitkey` (Server-assisted threshold signatures and PKE)
14. `minimpc` (Threshold AES+SHA+MAC and gadgets)
15. `maestro` (T-AES, T-SHA, T-MAC and gadgets)
16. `amber` (Threshold Lattice-based KEM)
17. `hermine` (Threshold Sign [Lattice-based])
18. `least` (Threshold Sign [code-based group-actions])
19. `tanuki` (Threshold Lattice-based Signature)
20. `vinaigrette` (Threshold UOV+MAYO Signatures)
21. `pantheria` (RLWE-based FHE and Threshold FHE)
22. `zama-tfhe` (TFHE, Threshold FHE)
23. `zama-zhenith` (ZKP)
24. `piver` (Verifiable Secret Sharing)
25. `schmivitz` (VOLEith-based ZKPoK)
26. `smallwood` (Hash-based ZKPoK)

(End of file - total 200 lines)










hash/
|-    /blake2b
|-    /blake2s
|-    /blake3
|-    /sha224
|-    /sha256
|-    /sha384
|-    /sha512
|-    /sha512-224
|-    /sha512-256
|-    /sm3
|-    /has160
|-    /md2
|-    /md4
|-    /md5
|-    /nt
|-    /ripemd128
|-    /ripemd160
|-    /ripemd256
|-    /ripemd320
|-    /sha0
|-    /sha1
|-    /whirlpool
|-    /argon2d
|-    /argon2i
|-    /argon2id
|-    /bcrypt
|-    /catena
|-    /lyra2
|-    /scrypt
|-    /yescrypt
|-    /balloon
|-    /pomelo
|-    /makwa
|-    /keccak256
|-    /sha3-224
|-    /sha3-256
|-    /sha3-384
|-    /sha3-512
|-    /shake128
|-    /shake256
|-    /skein256
|-    /skein512
|-    /skein1024
|-    /kmac128
|_    /kmac256