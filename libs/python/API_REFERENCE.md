# NextSSL Python API Quick Reference

## Import

```python
import nextssl
import nextssl.root
import nextssl.unsafe
```

## Hash Functions

```python
# One-shot digest
digest = nextssl.hash.digest(b"data", nextssl.HashAlgorithm.SHA256)

# Class-based
hasher = nextssl.Hash(nextssl.HashAlgorithm.BLAKE3)
output = hasher.digest(b"data")
hex_output = hasher.hexdigest(b"data")

# BLAKE2 (keyed MAC mode)
blake = nextssl.BLAKE2(nextssl.HashAlgorithm.BLAKE2B, key=b"secret", digest_size=32)
mac = blake.digest(b"data")

# SHAKE (XOF - arbitrary output)
shake = nextssl.SHAKE(nextssl.HashAlgorithm.SHAKE256)
output = shake.digest(b"data", output_length=64)

# Argon2 (password hashing)
argon = nextssl.Argon2(nextssl.HashAlgorithm.ARGON2ID)
hash_encoded = argon.hash_password(b"password", salt_length=16, time_cost=3, memory_cost=65536, parallelism=4)
is_valid = argon.verify_password(hash_encoded, b"password")
hash_raw = argon.hash_raw(b"password", salt=b"0"*16, hash_length=32, time_cost=3, memory_cost=65536, parallelism=4)
```

**Algorithms**: SHA-224/256/384/512(/224/256), SHA3-224/256/384/512, BLAKE2b/s/3, Keccak-224/256/384/512, SHAKE128/256, Argon2d/i/id, MD5, SHA1, RIPEMD160, Whirlpool, NT Hash

## Post-Quantum Cryptography

### KEM (Key Encapsulation)

```python
# ML-KEM (Kyber)
kem = nextssl.KEM(nextssl.KEMAlgorithm.ML_KEM_768)
public_key, secret_key = kem.keypair()
ciphertext, shared_secret = kem.encapsulate(public_key)
shared_secret_decaps = kem.decapsulate(ciphertext, secret_key)
```

**Algorithms**: ML-KEM-512/768/1024, HQC-128/192/256, McEliece-348864(/F)/460896(/F)/6688128(/F)/6960119(/F)/8192128(/F)

### Digital Signatures

```python
# ML-DSA (Dilithium)
signer = nextssl.Sign(nextssl.SignAlgorithm.ML_DSA_65)
public_key, secret_key = signer.keypair()
signature = signer.sign(b"message", secret_key)
is_valid = signer.verify(b"message", signature, public_key)
```

**Algorithms**: ML-DSA-44/65/87, Falcon-512/1024, SPHINCS+-SHAKE-128F/S-simple/robust, SPHINCS+-SHAKE-192F/S-simple/robust, SPHINCS+-SHAKE-256F/S-simple/robust, SPHINCS+-SHA2-128F/S-simple/robust, SPHINCS+-SHA2-192F/S-simple/robust, SPHINCS+-SHA2-256F/S-simple/robust

## Symmetric Encryption

### AES

```python
# AES-GCM (AEAD)
cipher = nextssl.AES(key=b"0"*32, mode=nextssl.AESMode.GCM)
ciphertext, tag = cipher.encrypt(b"plaintext", nonce=b"0"*12, aad=b"metadata")
plaintext = cipher.decrypt(ciphertext, nonce=b"0"*12, tag=tag, aad=b"metadata")
```

**Modes**: ECB, CBC, CFB, OFB, CTR, XTS, KW, FPE_FF1, FPE_FF3, GCM, CCM, OCB, EAX, GCM_SIV, SIV, POLY1305

### ChaCha20-Poly1305

```python
chacha = nextssl.ChaCha20Poly1305()
ciphertext, tag = chacha.encrypt(key=b"0"*32, nonce=b"0"*24, plaintext=b"data", aad=b"metadata")
plaintext = chacha.decrypt(key=b"0"*32, nonce=b"0"*24, ciphertext=ciphertext, tag=tag, aad=b"metadata")
```

## Elliptic Curve Cryptography

### Ed25519 (Signatures)

```python
ed = nextssl.Ed25519()
private_key, public_key = ed.keypair()
signature = ed.sign(private_key, b"message")
is_valid = ed.verify(public_key, b"message", signature)
```

### Curve25519 (Key Exchange)

```python
curve = nextssl.Curve25519()
sk_alice, pk_alice = curve.keypair()
sk_bob, pk_bob = curve.keypair()
shared_secret = curve.scalarmult(sk_alice, pk_bob)
```

**Curves**: Ed25519, Ed448, Curve25519, Curve448, Ristretto255, Elligator2

## Message Authentication Codes

```python
# HMAC-SHA256
mac = nextssl.MAC(nextssl.MACAlgorithm.HMAC_SHA256, key=b"secret")
tag = mac.compute(b"data")
is_valid = mac.verify(b"data", tag)

# SipHash
siphash = nextssl.SipHash(c=2, d=4, output_size=8)
tag = siphash.compute(key=b"0"*16, data=b"data")
```

**Algorithms**: HMAC-SHA256/512/SHA3-256/512/SHA1/MD5, CMAC-AES, Poly1305, AES-Poly1305, SipHash-2-4/4-8

## Key Derivation Functions

```python
# HKDF
hkdf = nextssl.HKDF(nextssl.KDFAlgorithm.HKDF_SHA256)
derived_key = hkdf.derive(salt=b"salt", ikm=b"input", info=b"context", length=32)

# KDF-SHAKE256
kdf = nextssl.KDF_SHAKE256()
key = kdf.derive(ikm=b"input", info=b"context", length=64)

# TLS 1.3
tls_hkdf = nextssl.TLS13_HKDF()
key = tls_hkdf.expand_label(prk=b"0"*32, label="key", context=b"", length=16)
```

**Functions**: HKDF-SHA256/SHA3-256/SHA3-512, KDF-SHAKE256, HKDF-Expand-Label

## Encoding

```python
# Base64
encoded = nextssl.b64encode(b"data")
decoded = nextssl.b64decode(encoded)

# Base64 URL-safe
encoded_url = nextssl.b64encode(b"data", url_safe=True)

# Hex
hex_str = nextssl.hexencode(b"data", uppercase=True)
decoded = nextssl.hexdecode(hex_str)

# FlexFrame-70
ff = nextssl.FlexFrame70()
encoded = ff.encode(b"data", metadata=b"meta")
data, metadata = ff.decode(encoded)
```

## DHCM (Dynamic Hash Cost Model)

```python
dhcm = nextssl.DHCM()
result = dhcm.calculate(
    algorithm=nextssl.DHCMAlgorithm.ARGON2ID,
    difficulty=nextssl.DHCMDifficultyModel.HIGH
)
print(f"Cost: {result.cost}, Recommended: {result.recommended_params}")
```

## Proof-of-Work

```python
# Client
client = nextssl.PoWClient(nextssl.PoWAlgorithm.SHA256)
nonce, proof = client.solve(challenge=b"challenge_data", difficulty=20)

# Server
server = nextssl.PoWServer(nextssl.PoWAlgorithm.SHA256)
is_valid = server.verify(challenge=b"challenge_data", nonce=nonce, proof=proof, difficulty=20)
```

## Root-Level Operations (Testing Only!)

```python
import nextssl.root

# Seed DRBG (deterministic randomness)
nextssl.root.seed_drbg(b"0" * 48)  # 48 bytes for AES-256 CTR_DRBG

# Reseed
nextssl.root.reseed_drbg(b"additional_entropy" * 3)

# ⚠️ DANGER: User Determined Byte Feeder (complete control)
nextssl.root.set_udbf(b"predefined random bytes for NIST KAT...")
# ... perform deterministic tests ...
nextssl.root.clear_udbf()  # Restore system randomness
```

## Unsafe/Legacy Algorithms (⚠️ BROKEN!)

```python
import nextssl.unsafe

# MD5 (collision attacks!)
md5_hash = nextssl.unsafe.md5(b"data")

# SHA1 (SHAttered attack!)
sha1_hash = nextssl.unsafe.sha1(b"data")

# Completely broken
md4_hash = nextssl.unsafe.md4(b"data")
sha0_hash = nextssl.unsafe.sha0(b"data")
md2_hash = nextssl.unsafe.md2(b"data")

# Class-based
unsafe_hash = nextssl.unsafe.UnsafeHash(nextssl.unsafe.UnsafeHashAlgorithm.RIPEMD128)
digest = unsafe_hash.digest(b"data")
```

**⚠️ WARNING**: These are cryptographically broken! Use only for:
- Legacy system compatibility
- Historical research  
- Non-security checksums

**NEVER use for**:
- Password hashing
- Digital signatures
- Data integrity
- Any security purpose

## Error Handling

All functions raise `ValueError` on:
- Invalid parameters (key size, algorithm, etc.)
- Cryptographic failures (verification, decryption)
- Library loading errors

```python
try:
    kem = nextssl.KEM(nextssl.KEMAlgorithm.ML_KEM_768)
    pk, sk = kem.keypair()
except ValueError as e:
    print(f"Error: {e}")
```

## Platform Support

- **Windows**: Loads `.dll` from `bin/windows/`
- **Linux**: Loads `.so` from `bin/linux/`
- **macOS**: Loads `.dylib` from `bin/mac/`

Library tiers (auto-selected):
1. `partial/` - Individual algorithm modules
2. `base/` - Combined core modules
3. `main/` - Single full binary
4. System library (optional, via `use_system=True`)

---

For complete documentation and examples, see [PYTHON_README.md](PYTHON_README.md).
