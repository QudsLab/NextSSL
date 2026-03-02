# API Reference

NextSSL exposes two build variants from a single unified header name
(`nextssl.h`).  Both share the same base function set; they differ in how
advanced operations are expressed.

---

## Variants

| | Full | Lite |
|---|---|---|
| Binary size | ~5 MB | ~500 KB |
| Algorithm count | 40+ | 9 |
| PQ operations | Separate `_pq_*` functions | `pqc` flag on unified functions |
| Nonce handling | Auto-generated (embedded in output) | Caller supplies nonce |
| Salt handling | Auto-generated (embedded in hash string) | Caller supplies salt |
| Legacy algorithms | ✓ (COMPATIBILITY / RESEARCH profiles) | — |
| `nextssl_root_*` | ✓ | ✓ |

---

## Quick Start (Full Variant)

```c
#include <nextssl.h>

// 1. Initialize (optional — auto-called on first use)
nextssl_init(0);  // 0 = MODERN profile

// 2. Encrypt
uint8_t key[32] = { /* ... your key ... */ };
uint8_t ct[1024];
size_t ct_len;
nextssl_encrypt(key, plaintext, plaintext_len, ct, &ct_len);

// 3. Decrypt
uint8_t pt[1024];
size_t pt_len;
nextssl_decrypt(key, ct, ct_len, pt, &pt_len);

// 4. Cleanup
nextssl_cleanup();
```

Output from `nextssl_encrypt` is `[12-byte nonce][ciphertext][16-byte tag]`
(total: `plaintext_len + 28`).

---

## Quick Start (Lite Variant)

```c
#include <nextssl.h>   // same name, different build

uint8_t key[32], nonce[12], ct[20];
nextssl_random(nonce, 12);                           // caller generates nonce
nextssl_encrypt(key, nonce, plaintext, 4, ct);       // nonce is a parameter
```

Key differences from full:

- `nextssl_encrypt/decrypt` take an explicit `nonce[12]` parameter.
- `nextssl_password_hash/verify` take an explicit `salt[16]` parameter.
- PQ operations use `nextssl_keygen(pk, sk, 1)` and `nextssl_sign(…, 1)`
  with a `pqc` flag instead of separate `nextssl_pq_*` functions.

---

## Root Interface

Both variants include `root/nextssl_root.h` automatically via the main header.
This exposes the explicit-algorithm bypass functions (`nextssl_root_sha256`,
`nextssl_root_aes256gcm_encrypt`, etc.).

> The include path itself is the warning: if you are using root functions in
> application code, reconsider.

See [docs/api/ROOT.md](ROOT.md) for the full function table and guidance.

---

## Reference Files

| File | Contents |
|---|---|
| [FUNCTIONS.md](FUNCTIONS.md) | Full function signatures for both variants |
| [ROOT.md](ROOT.md) | Explicit-algorithm bypass interface |
| [PROFILES.md](PROFILES.md) | Profiles, algorithm enums, config struct, error codes |
| [DHCM.md](DHCM.md) | DHCM subsystem API |
| [CHANGELOG.md](CHANGELOG.md) | API-level change history |
