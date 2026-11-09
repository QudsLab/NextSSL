# KAT sources

`cavp-hmac-drbg.json`, `cavp-hash-drbg.json`, `cavp-ctr-drbg.json` come from NIST CAVP `drbgtestvectors.zip`
(`drbgvectors_no_reseed.zip`: `HMAC_DRBG.rsp`, `Hash_DRBG.rsp`, `CTR_DRBG.rsp`, PredictionResistance = False).
URL: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
sha256 of the zip: `5f7e5658ebd5b4e6785a7b12fa32333511d2acc2f2d9c5ae1ffa16b699377769`.

Subset rule: the first 2 vectors of every parameter group (entropy, nonce, personalization and additional-input
lengths, returned bits) for HMAC_DRBG and Hash_DRBG with SHA-1, SHA-224, SHA-256 and SHA-512 (SHA-1 needs the
`compose-all` feature and is skipped, and named as skipped, without it), and for CTR_DRBG with AES-128, AES-192
and AES-256, both `use df` and `no df`. Replay: instantiate, generate (additional input 1, discarded), generate
(additional input 2) and compare with `ReturnedBits`. Not covered: SHA-384, SHA-512/224, SHA-512/256, TDEA, the
prediction-resistance sets, reseed vectors.

Other vectors are inline in `tests/engine.rs`: RFC 4231 case 1, RFC 5869 case 1, RFC 7914 PBKDF2-HMAC-SHA-256,
RFC 4493 AES-CMAC (empty message), NIST SP 800-38A F.2.1 AES-128-CBC and the hashcash.org stamp
`1:20:060408:adam@cypherspace.org::1QTjaYd7niiQA/sc:ePa`.
