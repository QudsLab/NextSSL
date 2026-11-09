# Envelope format (`nxs1`)

Binary: COSE_Encrypt0 (CBOR tag 16) or COSE_Sign1 (tag 18), RFC 9052. Text form: `nxs1.` + base64url without padding.
Code: `crates/nextssl/src/envelope`. The algorithm is named in the protected header by its COSE id from `algo.toml` `cose_alg`.

| Algorithm | COSE id | Source |
|---|---|---|
| aes-256-gcm | 3 | IANA (A256GCM) |
| chacha20-poly1305 (IETF, when imported) | 24 | IANA |
| ed25519 | -19 | IANA (RFC 9864) |
| ml-dsa-65 | -49 | IANA (RFC 9964) |
| hmac-sha256 | 5 | IANA |
| xchacha20-poly1305 | -65800 | private use (no IANA entry) |
| argon2id | -65601 | private use |
| blake2b-512 | -65700 | private use |

Private-use ids are below -65536. `cargo xtask gen` rejects two algorithms with the same `cose_alg`.

Password envelopes add the critical private header `-66000`: `[kdf_cose_alg, salt, {param: uint}]`, holding every KDF parameter.

Decoder rules: size limit (default 64 MiB), CBOR depth and item limits, definite lengths only, expected tag, `alg` protected and registered, tier allowed by policy (safe API: safe + standard), `crit` protected and fully understood, KDF cost schema-validated and capped.
