# NextSSL Python

Python bindings for the [NextSSL](https://github.com/QudsLab/NextSSL) cryptographic library.

NextSSL is a next-generation C security library providing AES-256-GCM, ChaCha20-Poly1305,
SHA-2/3/BLAKE3, Argon2id, X25519, Ed25519, ML-KEM, ML-DSA and more under a single
unified API.

---

## Installation

```sh
pip install nextssl
```

Platform-specific wheels are published for Windows (x86-64), Linux (x86-64), and macOS (x86-64).

---

## Quick Start

```python
import nextssl

# Initialize (optional — auto-called on first use)
nextssl.init(0)  # 0 = MODERN profile

# Random bytes
key = nextssl.random_bytes(32)

# Encrypt / Decrypt
ciphertext = nextssl.encrypt(key, b"hello world")
plaintext  = nextssl.decrypt(key, ciphertext)
assert plaintext == b"hello world"

# Hash (SHA-256)
digest = nextssl.hash(b"hello world")

# Password hashing (Argon2id)
stored = nextssl.password_hash("my_password")
assert nextssl.password_verify("my_password", stored)

# Cleanup
nextssl.cleanup()
```

---

## Profiles

| Index | Name | Description |
|---|---|---|
| 0 | MODERN | SHA-256, AES-256-GCM, Ed25519, X25519 (default) |
| 1 | COMPLIANCE | FIPS/NIST aligned |
| 2 | PQC | Post-quantum algorithms |
| 3 | COMPATIBILITY | Includes legacy algorithms |
| 4 | EMBEDDED | ChaCha20-Poly1305, small footprint |
| 5 | RESEARCH | All algorithms including unsafe |

---

## License

Apache 2.0. See [LICENSE](../../LICENSE).
