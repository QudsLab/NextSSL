# NextSSL Python Library - Complete Algorithm Coverage

Comprehensive Python bindings for NextSSL cryptographic library with **100+ algorithms**.

## 📦 Installation

```bash
pip install nextssl
```

## 🔐 Algorithm Coverage

### Hash Functions (40+)

#### Fast Hashes
- **SHA-2 Family**: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- **SHA-3 Family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- **BLAKE Family**: BLAKE2b, BLAKE2s, BLAKE3
- **Keccak**: All SHA-3 variants plus original Keccak

#### Memory-Hard Hashes
- **Argon2**: Argon2d, Argon2i, Argon2id (winner of Password Hashing Competition)

#### Sponge Functions (XOF)
- **SHAKE**: SHAKE128, SHAKE256 (arbitrary output length)

#### Legacy Alive (deprecated, but not broken)
- **MD5**: For checksums only (collision attacks exist)
- **SHA-1**: For legacy systems (SHAttered attack)
- **RIPEMD-160**: Bitcoin compatibility
- **Whirlpool**: ISO/IEC standard
- **NT Hash**: Windows NTLM compatibility

#### Legacy Unsafe (⚠️ BROKEN - in `unsafe` module)
- **MD2, MD4**: Completely broken
- **SHA-0**: Withdrawn 1995
- **HAS-160**: Weak Korean standard
- **RIPEMD-128/256/320**: Insufficient security

### Post-Quantum Cryptography (30+)

#### KEM (Key Encapsulation)
- **ML-KEM (Kyber)**: 512, 768, 1024 (NIST standard)
- **HQC**: 128, 192, 256
- **Classic McEliece**: 10 variants (348864, 460896, 6688128, 6960119, 8192128 + F variants)

#### Digital Signatures
- **ML-DSA (Dilithium)**: 44, 65, 87 (NIST standard)
- **Falcon**: 512, 1024
- **SPHINCS+**: 24 variants (SHAKE/SHA2, 128F/S, 192F/S, 256F/S, simple/robust)

### Symmetric Encryption (15+ modes)

#### AES Modes
- **Basic**: ECB, CBC, CFB, OFB, CTR
- **Disk Encryption**: XTS
- **Key Wrap**: KW
- **Format-Preserving**: FPE-FF1, FPE-FF3
- **AEAD**: GCM, CCM, OCB, EAX, GCM-SIV, SIV, Poly1305

#### Stream Ciphers
- **ChaCha20-Poly1305**: With XChaCha20 (24-byte nonce)

### Elliptic Curve Cryptography (5 curves)

- **Ed25519**: Fast EdDSA signatures (32-byte keys)
- **Ed448**: High-security EdDSA (57-byte keys)
- **Curve25519 (X25519)**: ECDH key exchange
- **Curve448 (X448)**: High-security ECDH
- **Ristretto255**: Prime-order group (no cofactor issues)
- **Elligator2**: Indistinguishability for Curve25519

### Message Authentication Codes (6+)

- **HMAC**: SHA-256, SHA-512, SHA3-256, SHA3-512, SHA-1, MD5
- **CMAC**: AES-based
- **Poly1305**: High-speed MAC
- **AES-Poly1305**: Integrated MAC
- **SipHash**: 2-4, 4-8 (for hash tables)

### Key Derivation Functions (5)

- **HKDF**: SHA-256, SHA3-256, SHA3-512 variants
- **KDF-SHAKE256**: SHAKE-based KDF
- **TLS 1.3**: HKDF-Expand-Label

### Encoding Utilities

- **Base64**: Standard and URL-safe
- **Hexadecimal**: Uppercase/lowercase
- **FlexFrame-70**: Structured data encoding

### Special Features

#### DHCM (Dynamic Hash Cost Model)
Cost modeling for ALL 25+ hash algorithms to select optimal algorithm based on security/performance requirements.

#### Proof-of-Work
Client/server PoW system supporting all hash algorithms.

#### Root-Level Operations (in `root` module)
- **DRBG**: CTR_DRBG (AES-256) for deterministic randomness
- **UDBF**: User Determined Byte Feeder for complete determinism (testing only!)

## 🚀 Quick Start

### Hash Functions

```python
import nextssl

# Modern secure hashes
digest = nextssl.hash.digest(b"Hello, World!", nextssl.HashAlgorithm.SHA256)
print(digest.hex())

# Memory-hard password hashing
hasher = nextssl.Argon2(nextssl.HashAlgorithm.ARGON2ID)
password_hash = hasher.hash_password(b"my_password")
is_valid = hasher.verify_password(password_hash, b"my_password")

# XOF (arbitrary output length)
shake = nextssl.SHAKE(nextssl.HashAlgorithm.SHAKE256)
output = shake.digest(b"data", output_length=64)

# Legacy (use only for compatibility!)
import nextssl.unsafe
md5_hash = nextssl.unsafe.md5(b"data")  # ⚠️ BROKEN - checksums only!
```

### Post-Quantum Cryptography

```python
import nextssl

# ML-KEM (quantum-safe key exchange)
kem = nextssl.KEM(nextssl.KEMAlgorithm.ML_KEM_768)
pk, sk = kem.keypair()
ciphertext, shared_secret_alice = kem.encapsulate(pk)
shared_secret_bob = kem.decapsulate(ciphertext, sk)
assert shared_secret_alice == shared_secret_bob

# ML-DSA (quantum-safe signatures)
signer = nextssl.Sign(nextssl.SignAlgorithm.ML_DSA_65)
pk, sk = signer.keypair()
signature = signer.sign(b"Important message", sk)
is_valid = signer.verify(b"Important message", signature, pk)
```

### AES Encryption

```python
import nextssl

# AES-GCM (authenticated encryption)
cipher = nextssl.AES(key=b"0" * 32, mode=nextssl.AESMode.GCM)
nonce = b"0" * 12
ciphertext, tag = cipher.encrypt(b"Secret data", nonce=nonce)
plaintext = cipher.decrypt(ciphertext, nonce=nonce, tag=tag)

# ChaCha20-Poly1305
chacha = nextssl.ChaCha20Poly1305()
ct, tag = chacha.encrypt(key=b"0"*32, nonce=b"0"*24, plaintext=b"data")
```

### Elliptic Curves

```python
import nextssl

# Ed25519 signatures
ed = nextssl.Ed25519()
sk, pk = ed.keypair()
signature = ed.sign(sk, b"Message")
is_valid = ed.verify(pk, b"Message", signature)

# Curve25519 key exchange
curve = nextssl.Curve25519()
sk_alice, pk_alice = curve.keypair()
sk_bob, pk_bob = curve.keypair()
shared_alice = curve.scalarmult(sk_alice, pk_bob)
shared_bob = curve.scalarmult(sk_bob, pk_alice)
assert shared_alice == shared_bob
```

### Key Derivation

```python
import nextssl

# HKDF (extract-and-expand)
hkdf = nextssl.HKDF(nextssl.KDFAlgorithm.HKDF_SHA256)
key = hkdf.derive(
    salt=b"salt",
    ikm=b"input keying material",
    info=b"context",
    length=32
)

# SHAKE256-KDF
kdf = nextssl.KDF_SHAKE256()
derived = kdf.derive(ikm=b"input", info=b"context", length=64)
```

### DHCM (Cost Modeling)

```python
import nextssl

# Find best hash for your requirements
dhcm = nextssl.DHCM()
result = dhcm.calculate(
    algorithm=nextssl.DHCMAlgorithm.SHA256,
    difficulty=nextssl.DHCMDifficultyModel.MEDIUM
)
print(f"Cost score: {result.cost}")
```

### Root-Level Control (Testing Only!)

```python
import nextssl.root

# Seed DRBG for deterministic tests
nextssl.root.seed_drbg(b"0" * 48)

# ⚠️ DANGER: Complete control over randomness (NIST KAT vectors)
nextssl.root.set_udbf(b"predefined random bytes...")
# ... run tests ...
nextssl.root.clear_udbf()  # Restore system randomness
```

## 📚 Module Organization

```python
import nextssl

# Core modules
nextssl.hash          # All hash functions
nextssl.pqc           # Post-quantum crypto (KEM, Sign)
nextssl.primitives    # AES, ChaCha20, ECC, MAC
nextssl.kdf           # Key derivation
nextssl.encoding      # Base64, Hex, FlexFrame-70
nextssl.dhcm          # Dynamic Hash Cost Model
nextssl.pow           # Proof-of-Work

# Special namespaces
nextssl.root          # DRBG, UDBF (testing only)
nextssl.unsafe        # Broken algorithms (legacy compatibility)
```

## ⚠️ Security Warnings

### Never Use `nextssl.unsafe` for Security!

The `unsafe` module contains **cryptographically broken** algorithms:
- **MD2, MD4**: Trivial collisions
- **SHA-0**: Withdrawn before publication
- **SHA-1**: SHAttered attack (2017)
- **MD5**: Collision attacks (2004), chosen-prefix collisions (2012)

Use these **only** for:
- Legacy system compatibility
- Historical research
- Breaking old protocols
- Checksums (non-security)

### Never Use `nextssl.root.set_udbf()` in Production!

UDBF gives complete control over "randomness" - **only use for**:
- NIST Known Answer Tests (KAT)
- Deterministic unit tests
- Debugging cryptographic implementations

**It will destroy all security if misused!**

## 🔧 Binary Loading

NextSSL automatically loads native libraries:

```
bin/
  windows/  # .dll files
  linux/    # .so files  
  mac/      # .dylib files
    partial/  # Individual algorithm modules
    base/     # Core combined binaries
    main/     # Full combined binary
```

Tiers:
- **partial**: Individual DLLs per algorithm (dhcm, hash, pqc, core)
- **base**: Combined binaries with core algorithms
- **main**: Single binary with everything

## 📖 Documentation

Full API documentation: [docs.nextssl.org](https://docs.nextssl.org)

## 📄 License

See [LICENSE](../../LICENSE) file.

## 🤝 Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md).

## 🔗 Links

- **GitHub**: https://github.com/your-org/nextssl
- **PyPI**: https://pypi.org/project/nextssl/
- **Docs**: https://docs.nextssl.org
- **Security**: See [SECURITY.md](../../SECURITY.md)

---

**Version**: 0.0.1  
**Status**: Beta - API may change before 1.0.0
