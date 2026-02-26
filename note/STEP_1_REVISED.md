# ⚠️ SUPERSEDED BY STEP_1_FINAL.md

**Please see**: [STEP_1_FINAL.md](STEP_1_FINAL.md) for the corrected version.

**Reason**: Algorithm counts were still inaccurate. The final version correctly identifies:
- **35 hash algorithms** (not 29) - includes all Whirlpool variants, complete Keccak/SHAKE family
- **38 core algorithms** (not 32) - includes complete MAC/KDF inventory  
- **134 total algorithms** (verified against ALGORITHM.md)

---

# STEP 1: NextSSL Testing & Workflow Enhancement Plan (REVISED - OUTDATED)

**Date**: 2026-02-26  
**Goal**: Implement comprehensive functional testing with proper logging (mirroring binary structure) + optimize CI/CD workflow

**Key Change**: Test structure and logs now mirror the `/bin/` directory organization exactly, matching the division system used for binary generation.

**Status**: ⚠️ OUTDATED - See STEP_1_FINAL.md

---

## Part A: Workflow Command Flags (GitHub Actions)

### Problem Statement
Currently, every commit triggers full CI pipeline (build → test → publish). This is wasteful when:
- Updating test scripts (no lib changes)
- Updating documentation (no lib changes)
- Updating notes/examples (no lib changes)
- Testing locally before publishing
- Regenerating binaries without publishing

**Solution**: Smart flag-based workflow control

### Proposed Command Flags

```bash
# 1. Silent commits - Skip CI entirely (default)
git commit -m "docs: updated README"
git commit -m "test: fixed test script"
git commit -m "note: added examples"

# 2. Test only - Run tests, no publish, no bin generation
git commit -m "fix: something --test"
git commit -m "refactor: cleanup --test"

# 3. Regenerate binaries - Rebuild bins + test, no publish
git commit -m "refactor: core changes --gen"
git commit -m "feat: new algorithm --gen"

# 4. Publish test version - Build + test + publish to TestPyPI
git commit -m "feat: new feature --v 0.0.10 --test"
git commit -m "fix: bug fix --v 0.0.11 --test"

# 5. Publish beta - Build + test + publish beta to TestPyPI
git commit -m "feat: experimental API --v 0.1.0-beta.1 --beta"

# 6. Publish release - Build + test + publish to PyPI
git commit -m "release: stable version --v 1.0.0 --release"
```

### Flag Hierarchy & Logic

| Flags Present | CI Trigger? | Run Tests? | Gen Bins? | Publish? | Target |
|--------------|-------------|------------|-----------|----------|---------|
| (none)       | ❌ Skip     | -          | -         | -        | -       |
| `--test`     | ✅ Run      | ✅ Yes     | ❌ No     | ❌ No    | -       |
| `--gen`      | ✅ Run      | ✅ Yes     | ✅ Yes    | ❌ No    | -       |
| `--v X.Y.Z --test` | ✅ Run | ✅ Yes | ✅ Yes | ✅ Yes | TestPyPI |
| `--v X.Y.Z --beta` | ✅ Run | ✅ Yes | ✅ Yes | ✅ Yes | TestPyPI |
| `--v X.Y.Z --release` | ✅ Run | ✅ Yes | ✅ Yes | ✅ Yes | PyPI |

### Workflow Implementation

**File**: `.github/workflows/publish_python.yml`

**Step 1**: Parse commit message for flags
```yaml
- name: Parse commit flags
  id: flags
  run: |
    MSG="${{ github.event.head_commit.message }}"
    
    # Check for any CI trigger flag
    if echo "$MSG" | grep -qE "(--test|--gen|--v [0-9]|--release|--beta)"; then
      echo "ci_enabled=true" >> $GITHUB_OUTPUT
    else
      echo "ci_enabled=false" >> $GITHUB_OUTPUT
      exit 0  # Skip entire workflow
    fi
    
    # Parse individual flags
    echo "run_tests=$(echo $MSG | grep -q -- '--test' && echo true || echo false)" >> $GITHUB_OUTPUT
    echo "gen_bins=$(echo $MSG | grep -qE '(--gen|--v [0-9])' && echo true || echo false)" >> $GITHUB_OUTPUT
    echo "should_publish=$(echo $MSG | grep -qE '(--v [0-9])' && echo true || echo false)" >> $GITHUB_OUTPUT
    
    # Extract version
    if echo "$MSG" | grep -qE '--v [0-9]'; then
      VERSION=$(echo "$MSG" | grep -oE '\-\-v [0-9]+\.[0-9]+\.[0-9]+(\-[a-z0-9\.]+)?' | sed 's/--v //')
      echo "version=$VERSION" >> $GITHUB_OUTPUT
    fi
    
    # Determine publish mode
    if echo "$MSG" | grep -q -- '--release'; then
      echo "publish_mode=release" >> $GITHUB_OUTPUT
    elif echo "$MSG" | grep -q -- '--beta'; then
      echo "publish_mode=beta" >> $GITHUB_OUTPUT
    elif echo "$MSG" | grep -q -- '--test'; then
      echo "publish_mode=test" >> $GITHUB_OUTPUT
    fi
```

**Step 2**: Conditional jobs
```yaml
jobs:
  generate-binaries:
    if: steps.flags.outputs.gen_bins == 'true'
    # ... bin generation logic
  
  test:
    if: steps.flags.outputs.ci_enabled == 'true'
    # ... test logic
  
  publish:
    if: steps.flags.outputs.should_publish == 'true'
    # ... publish logic with ${{ steps.flags.outputs.publish_mode }}
```

### Benefits
- ✅ **90% fewer CI runs** - Most commits (docs, tests, notes) skip CI
- ✅ **Fast feedback** - `--test` flag runs tests without publishing overhead
- ✅ **Controlled bin generation** - Only regenerate when C code changes
- ✅ **Clear intent** - Flags explicitly show what will happen
- ✅ **Version control** - Prevent accidental releases

---

## Part B: Binary & Test Organization (Matching Structure)

### Understanding the Division System

Looking at the `/bin/` directory structure reveals the actual organization:

```
bin/
├───windows/           # Platform: Windows (.dll)
├───linux/             # Platform: Linux (.so)
├───mac/               # Platform: macOS (.dylib)
└───web/               # Platform: WebAssembly (.wasm)
    ├───main/          # Tier 1: Combined binaries (all features)
    ├───base/          # Tier 2: Category binaries (hash, pqc, core, etc.)
    └───partial/       # Tier 3: Granular binaries (by algorithm family)
        ├───hash/
        │   ├───primitive_fast.wasm
        │   ├───primitive_memory_hard.wasm
        │   ├───primitive_sponge_xof.wasm
        │   ├───legacy_alive.wasm
        │   └───legacy_unsafe.wasm
        ├───dhcm/
        │   └───(same 5 categories as hash)
        ├───pow/
        │   ├───client/
        │   │   └───(same 5 hash categories)
        │   ├───server/
        │   │   └───(same 5 hash categories)
        │   └───combined/
        │       └───(same 5 hash categories)
        ├───core/
        │   ├───aes_modes.wasm
        │   ├───aes_aead.wasm
        │   ├───stream_aead.wasm
        │   ├───ecc.wasm
        │   └───macs.wasm
        └───pqc/
            ├───kem_lattice.wasm
            ├───kem_code_based.wasm
            ├───sign_lattice.wasm
            └───sign_hash_based.wasm
```

### Hash Algorithm Categories

**Hash algorithms are divided into 5 categories**:

1. **primitive_fast** (6 algorithms):
   - SHA-224, SHA-256, SHA-384, SHA-512
   - BLAKE2b, BLAKE2s, BLAKE3

2. **primitive_memory_hard** (3 algorithms):
   - Argon2d, Argon2i, Argon2id

3. **primitive_sponge_xof** (7 algorithms):
   - SHA3-224, SHA3-256, SHA3-384, SHA3-512
   - SHAKE-128, SHAKE-256
   - Keccak-256

4. **legacy_alive** (6 algorithms - older but still secure in some contexts):
   - MD5 (still used for checksums, NOT security)
   - SHA-1 (deprecated for signatures, still used in legacy systems)
   - RIPEMD-160
   - NT-Hash
   - Whirlpool
   - AES-ECB (as hash mode)

5. **legacy_unsafe** (7 algorithms - broken cryptographically):
   - MD2, MD4
   - SHA-0
   - HAS-160
   - RIPEMD-128, RIPEMD-256, RIPEMD-320

**Total hash algorithms: 29**

### DHCM & PoW Organization

DHCM and PoW both use **hash-based proof systems**, so they follow the same 5-category division:
- primitive_fast
- primitive_memory_hard
- primitive_sponge_xof
- legacy_alive
- legacy_unsafe

**PoW additionally splits by role**:
- `client/` - Client-side solving (5 hash categories)
- `server/` - Server-side verification (5 hash categories)
- `combined/` - Both client + server (5 hash categories)

**Total DHCM configurations: 5**  
**Total PoW configurations: 15** (5 categories × 3 roles)

### Core Cipher Organization

**Core is divided into 5 groups by cipher type**:

1. **aes_modes** (7+ modes):
   - ECB, CBC, CFB, OFB, CTR
   - XTS (disk encryption)
   - KW (key wrap)
   - FPE-FF1, FPE-FF3 (format-preserving encryption)

2. **aes_aead** (7 authenticated modes):
   - GCM (Galois Counter Mode)
   - CCM (Counter with CBC-MAC)
   - OCB (Offset Codebook)
   - EAX
   - GCM-SIV (nonce-misuse resistant)
   - SIV (Synthetic IV)
   - AES-POLY1305

3. **stream_aead** (1 algorithm):
   - ChaCha20-Poly1305

4. **ecc** (6 curves):
   - Ed25519 (Edwards curve signature)
   - Ed448 (Edwards curve signature)
   - Curve25519 (X25519 ECDH)
   - Curve448 (X448 ECDH)
   - Ristretto255 (prime-order group)
   - Elligator2 (point encoding)

5. **macs** (9+ algorithms):
   - AES-CMAC
   - SipHash-2-4, SipHash-4-8
   - HMAC-SHA256, HMAC-SHA512
   - HMAC-SHA3-256, HMAC-SHA3-512
   - KMAC-128, KMAC-256
   - POLY1305

**Total core algorithms: ~35**

### PQC Organization

**PQC is divided into 4 groups by algorithm family**:

1. **kem_lattice** (6 algorithms):
   - ML-KEM-512 (Kyber)
   - ML-KEM-768 (Kyber)
   - ML-KEM-1024 (Kyber)
   - HQC-128
   - HQC-192
   - HQC-256

2. **kem_code_based** (10 algorithms):
   - MCELIECE-348864, MCELIECE-348864f
   - MCELIECE-460896, MCELIECE-460896f
   - MCELIECE-6688128, MCELIECE-6688128f
   - MCELIECE-6960119, MCELIECE-6960119f
   - MCELIECE-8192128, MCELIECE-8192128f

3. **sign_lattice** (7 algorithms):
   - ML-DSA-44 (Dilithium)
   - ML-DSA-65 (Dilithium)
   - ML-DSA-87 (Dilithium)
   - Falcon-512
   - Falcon-1024
   - Falcon-Padded-512
   - Falcon-Padded-1024

4. **sign_hash_based** (12 algorithms):
   - SPHINCS-SHA2-128f-simple, SPHINCS-SHA2-128s-simple
   - SPHINCS-SHA2-192f-simple, SPHINCS-SHA2-192s-simple
   - SPHINCS-SHA2-256f-simple, SPHINCS-SHA2-256s-simple
   - SPHINCS-SHAKE-128f-simple, SPHINCS-SHAKE-128s-simple
   - SPHINCS-SHAKE-192f-simple, SPHINCS-SHAKE-192s-simple
   - SPHINCS-SHAKE-256f-simple, SPHINCS-SHAKE-256s-simple

**Total PQC algorithms: 35**

---

## Part C: Test Directory Structure (Mirroring Binary Organization)

### Test File Organization

```
tests/                                  # Repo root test directory
    test_all.py                         # Main entry point
    utils/                              # Test utilities
        __init__.py                     # Exports run_all(), TestLogger
        common.py                       # Shared: logger, vectors, constants
        
        hash/                           # Hash tests (5 categories)
            __init__.py
            test_primitive_fast.py      # 6 algorithms
            test_primitive_memory_hard.py  # 3 algorithms
            test_primitive_sponge_xof.py   # 7 algorithms
            test_legacy_alive.py        # 6 algorithms
            test_legacy_unsafe.py       # 7 algorithms
        
        dhcm/                           # DHCM tests (5 categories)
            __init__.py
            test_primitive_fast.py
            test_primitive_memory_hard.py
            test_primitive_sponge_xof.py
            test_legacy_alive.py
            test_legacy_unsafe.py
        
        pow/                            # PoW tests (3 roles × 5 categories)
            __init__.py
            client/
                __init__.py
                test_primitive_fast.py
                test_primitive_memory_hard.py
                test_primitive_sponge_xof.py
                test_legacy_alive.py
                test_legacy_unsafe.py
            server/
                __init__.py
                test_primitive_fast.py
                test_primitive_memory_hard.py
                test_primitive_sponge_xof.py
                test_legacy_alive.py
                test_legacy_unsafe.py
            combined/
                __init__.py
                test_primitive_fast.py
                test_primitive_memory_hard.py
                test_primitive_sponge_xof.py
                test_legacy_alive.py
                test_legacy_unsafe.py
        
        core/                           # Core tests (5 groups)
            __init__.py
            test_aes_modes.py           # 7+ modes
            test_aes_aead.py            # 7 AEAD modes
            test_stream_aead.py         # 1 algorithm
            test_ecc.py                 # 6 curves
            test_macs.py                # 9+ MAC algorithms
        
        pqc/                            # PQC tests (4 groups)
            __init__.py
            test_kem_lattice.py         # 6 algorithms
            test_kem_code_based.py      # 10 algorithms
            test_sign_lattice.py        # 7 algorithms
            test_sign_hash_based.py     # 12 algorithms
        
        root/                           # Root operations
            __init__.py
            test_drbg.py                # Deterministic RNG
            test_udbf.py                # User-defined byte function
        
        encoding/                       # Encoding utilities
            __init__.py
            test_base64.py
            test_hex.py
            test_flexframe.py
        
        kdf/                            # Key derivation
            __init__.py
            test_hkdf.py
            test_kdf_shake.py
            test_tls13_hkdf.py
```

### Log Directory Structure (Mirroring Tests & Binaries)

```
logs/
├───bin/                                # Binary generation logs
│   ├───main/
│   │   ├───system.log
│   │   ├───core.log
│   │   ├───hash.log
│   │   ├───dhcm.log
│   │   ├───pow.log
│   │   └───pqc.log
│   │
│   ├───base/
│   │   ├───core_cipher_main.log
│   │   ├───core_ecc_main.log
│   │   ├───core_mac_main.log
│   │   ├───hash_primitive.log
│   │   ├───hash_legacy.log
│   │   ├───dhcm_primitive.log
│   │   ├───dhcm_legacy.log
│   │   ├───pow_combined.log
│   │   ├───pow_client_primitive.log
│   │   ├───pow_client_legacy.log
│   │   ├───pow_server_primitive.log
│   │   ├───pow_server_legacy.log
│   │   ├───pqc_kem_main.log
│   │   └───pqc_sign_main.log
│   │
│   └───partial/
│       ├───hash/
│       │   ├───primitive_fast.log
│       │   ├───primitive_memory_hard.log
│       │   ├───primitive_sponge_xof.log
│       │   ├───legacy_alive.log
│       │   └───legacy_unsafe.log
│       │
│       ├───dhcm/
│       │   └───(same 5 logs as hash)
│       │
│       ├───pow/
│       │   ├───client/
│       │   │   └───(same 5 logs)
│       │   ├───server/
│       │   │   └───(same 5 logs)
│       │   └───combined/
│       │       └───(same 5 logs)
│       │
│       ├───core/
│       │   ├───aes_modes.log
│       │   ├───aes_aead.log
│       │   ├───stream_aead.log
│       │   ├───ecc.log
│       │   └───macs.log
│       │
│       └───pqc/
│           ├───kem_lattice.log
│           ├───kem_code_based.log
│           ├───sign_lattice.log
│           └───sign_hash_based.log
│
└───test/                               # Python library test logs
    ├───summary.log
    │
    ├───hash/
    │   ├───primitive_fast.log
    │   ├───primitive_memory_hard.log
    │   ├───primitive_sponge_xof.log
    │   ├───legacy_alive.log
    │   └───legacy_unsafe.log
    │
    ├───dhcm/
    │   └───(same 5 logs as hash)
    │
    ├───pow/
    │   ├───client/
    │   ├───server/
    │   └───combined/
    │
    ├───core/
    │   ├───aes_modes.log
    │   ├───aes_aead.log
    │   ├───stream_aead.log
    │   ├───ecc.log
    │   └───macs.log
    │
    ├───pqc/
    │   ├───kem_lattice.log
    │   ├───kem_code_based.log
    │   ├───sign_lattice.log
    │   └───sign_hash_based.log
    │
    ├───root/
    │   ├───drbg.log
    │   └───udbf.log
    │
    ├───encoding/
    │   ├───base64.log
    │   ├───hex.log
    │   └───flexframe.log
    │
    └───kdf/
        ├───hkdf.log
        ├───kdf_shake.log
        └───tls13_hkdf.log
```

**Key benefit**: Finding logs is easy - structure matches binaries and tests exactly.

---

## Part D: Testing Philosophy & Implementation

### Current Problem
Current test (`tests/test_all.py`) only validates:
- ✅ Enums exist
- ✅ Classes are callable
- ✅ Correct sizes/values

**Missing**:
- ❌ Actual encryption → decryption roundtrips
- ❌ Sign → verify cycles
- ❌ KEM encapsulate → decapsulate matching
- ❌ Known test vectors (KAT)
- ❌ Detailed logging like bin generator
- ❌ Error case testing (wrong key, tampered data)

### New Testing Philosophy

**"Test what users will do"**

Every test must perform REAL operations:
1. **Hash**: Hash data, verify against known vector
2. **Cipher**: Encrypt → Decrypt → Verify plaintext matches
3. **AEAD**: Encrypt+auth → Decrypt+verify → Check integrity
4. **PQC KEM**: Keygen → Encapsulate → Decapsulate → Verify shared secret matches
5. **PQC Sign**: Keygen → Sign → Verify(valid) → Verify(invalid) → Check results
6. **ECC**: Keygen → Sign/ECDH → Verify → Check correctness
7. **MAC**: Compute → Verify(valid) → Verify(invalid)
8. **KDF**: Derive → Check length/determinism
9. **Encoding**: Encode → Decode → Verify roundtrip
10. **DHCM**: Calculate → Check expected trials
11. **PoW**: Generate challenge → Solve → Verify

### Test Module Template

**Example**: `tests/utils/hash/test_primitive_fast.py`

```python
"""Test primitive_fast hash algorithms: SHA-224/256/384/512, BLAKE2b/s, BLAKE3."""

from ..common import TestLogger, VECTORS
import nextssl

def run(log):
    """Run all primitive_fast hash tests. log = TestLogger instance."""
    
    log.section("Primitive Fast Hash - Enum Validation")
    
    algorithms = [
        (nextssl.HashAlgorithm.SHA224, 224//8, "SHA-224"),
        (nextssl.HashAlgorithm.SHA256, 32, "SHA-256"),
        (nextssl.HashAlgorithm.SHA384, 48, "SHA-384"),
        (nextssl.HashAlgorithm.SHA512, 64, "SHA-512"),
        (nextssl.HashAlgorithm.BLAKE2B, 64, "BLAKE2b"),
        (nextssl.HashAlgorithm.BLAKE2S, 32, "BLAKE2s"),
        (nextssl.HashAlgorithm.BLAKE3, 32, "BLAKE3"),
    ]
    
    # Test 1: Enum existence and digest sizes
    for algo_enum, expected_size, name in algorithms:
        hasher = nextssl.Hash(algo_enum)
        if hasher.digest_size == expected_size:
            log.pass_(f"{name} structure", size=expected_size, value=algo_enum.value)
        else:
            log.fail(f"{name} structure", expected=expected_size, got=hasher.digest_size)
    
    log.section("Primitive Fast Hash - Known Answer Tests (KAT)")
    
    # Test 2: Known test vectors (NIST/RFC)
    test_vectors = {
        "SHA256": {
            b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "SHA512": {
            b"abc": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                   "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            b"": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                 "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        },
        # Add vectors for SHA-224, SHA-384, BLAKE2b, BLAKE2s, BLAKE3
    }
    
    for algo_name, vectors in test_vectors.items():
        algo_enum = getattr(nextssl.HashAlgorithm, algo_name)
        hasher = nextssl.Hash(algo_enum)
        
        for data, expected_hex in vectors.items():
            result = hasher.digest(data)
            result_hex = result.hex()
            
            log.data(f"{algo_name}({len(data)} bytes)", result_hex)
            
            if result_hex == expected_hex:
                log.pass_(f"{algo_name} KAT", input_len=len(data))
            else:
                log.fail(f"{algo_name} KAT", 
                        expected=expected_hex[:16]+"...", 
                        got=result_hex[:16]+"...")
    
    log.section("Primitive Fast Hash - Determinism")
    
    # Test 3: Same input produces same output
    test_data = b"nextssl test data for determinism check"
    for algo_enum, _, name in algorithms:
        hasher = nextssl.Hash(algo_enum)
        digest1 = hasher.digest(test_data)
        digest2 = hasher.digest(test_data)
        
        if digest1 == digest2:
            log.pass_(f"{name} determinism", matches=True)
        else:
            log.fail(f"{name} determinism", reason="outputs differ")
    
    log.section("Primitive Fast Hash - Collision Resistance")
    
    # Test 4: Different inputs produce different outputs
    data1 = b"nextssl"
    data2 = b"nextss1"  # One bit different
    
    for algo_enum, _, name in algorithms:
        hasher = nextssl.Hash(algo_enum)
        digest1 = hasher.digest(data1)
        digest2 = hasher.digest(data2)
        
        if digest1 != digest2:
            log.pass_(f"{name} collision", different=True)
        else:
            log.fail(f"{name} collision", reason="same output for different inputs")
```

### Logger Implementation

**File**: `tests/utils/common.py`

```python
"""Shared test infrastructure - logger, vectors, constants."""

import pathlib
import datetime
import sys

# Paths
_THIS_DIR = pathlib.Path(__file__).resolve().parent
TESTS_DIR = _THIS_DIR.parent
REPO_ROOT = TESTS_DIR.parent
LOG_DIR = REPO_ROOT / "logs" / "test"

class TestLogger:
    """Dual stdout + file logger with hex data logging (like bin generator)."""
    
    def __init__(self, name, subdir=""):
        """
        name: Module name (e.g., "test_primitive_fast")
        subdir: Subdirectory path (e.g., "hash" or "pow/client")
        """
        self.name = name
        self.passed = 0
        self.failed = 0
        
        # Create log directory matching structure
        if subdir:
            log_path = LOG_DIR / subdir
        else:
            log_path = LOG_DIR
        
        log_path.mkdir(parents=True, exist_ok=True)
        self.log_file = log_path / f"{name}.log"
        self.file = open(self.log_file, "w", encoding="utf-8")
        
        self._write_header()
    
    def _write_header(self):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self._out("=" * 70)
        self._out(f"{self.name}.log")
        self._out(ts)
        self._out("=" * 70)
    
    def _out(self, line):
        """Write to both stdout and file."""
        print(line)
        self.file.write(line + "\n")
        self.file.flush()
    
    def section(self, title):
        """Print section header."""
        self._out(f"\n{'='*70}")
        self._out(f"  {title}")
        self._out("=" * 70)
    
    def pass_(self, name, **details):
        """Log a passing test with optional details."""
        detail_str = "  ".join(f"{k}={v}" for k, v in details.items())
        self._out(f"[PASS] {name:<50} {detail_str}")
        self.passed += 1
    
    def fail(self, name, **details):
        """Log a failing test with optional details."""
        detail_str = "  ".join(f"{k}={v}" for k, v in details.items())
        self._out(f"[FAIL] {name:<50} {detail_str}")
        self.failed += 1
    
    def info(self, msg):
        """Log informational message."""
        self._out(f"[INFO] {msg}")
    
    def data(self, label, hex_data, max_len=64):
        """Log hex data (like bin generator logs)."""
        if len(hex_data) > max_len * 2:
            display = hex_data[:max_len*2] + "..."
        else:
            display = hex_data
        self._out(f"       {label}: {display}")
    
    def summary(self):
        """Write summary and return (passed, failed)."""
        total = self.passed + self.failed
        status = "PASS" if self.failed == 0 else "FAIL"
        
        self._out("\n" + "=" * 70)
        self._out("SUMMARY")
        self._out("=" * 70)
        self._out(f"Passed:  {self.passed}")
        self._out(f"Failed:  {self.failed}")
        self._out(f"Total:   {total}")
        self._out(f"Status:  {status}")
        self._out("=" * 70)
        
        self.file.close()
        return self.passed, self.failed

# Known test vectors (KAT) from NIST, RFC, etc.
VECTORS = {
    "SHA256": {
        b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    "SHA512": {
        b"abc": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
               "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        b"": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
             "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    },
    # Add more vectors for other algorithms
}
```

---

## Part E: Algorithm Count Summary (Corrected)

### By Category

| Category | Subcategory | Algorithm Count | Notes |
|----------|------------|----------------|-------|
| **Hash** | primitive_fast | 6 | SHA-2 family, BLAKE2/3 |
| | primitive_memory_hard | 3 | Argon2 variants |
| | primitive_sponge_xof | 7 | SHA-3 family, SHAKE, Keccak |
| | legacy_alive | 6 | Older but still used |
| | legacy_unsafe | 7 | Cryptographically broken |
| | **TOTAL** | **29** | |
|||
| **DHCM** | (uses hash categories) | 5 | One per hash category |
|||
| **PoW** | client | 5 | One per hash category |
| | server | 5 | One per hash category |
| | combined | 5 | One per hash category |
| | **TOTAL** | **15** | |
|||
| **Core** | aes_modes | 9 | Non-authenticated modes |
| | aes_aead | 7 | Authenticated encryption |
| | stream_aead | 1 | ChaCha20-Poly1305 |
| | ecc | 6 | Elliptic curves |
| | macs | 9 | Message authentication |
| | **TOTAL** | **32** | |
|||
| **PQC** | kem_lattice | 6 | ML-KEM, HQC |
| | kem_code_based | 10 | Classic McEliece |
| | sign_lattice | 7 | ML-DSA, Falcon |
| | sign_hash_based | 12 | SPHINCS+ |
| | **TOTAL** | **35** | |
|||
| **KDF** | | 5 | HKDF variants, TLS13 |
| **Encoding** | | 5 | Base64, Hex, FlexFrame |
| **Root** | | 2 | DRBG, UDBF |
|||
| **GRAND TOTAL** | | **128** | Functional algorithms |

---

## Part F: Implementation Steps

### Phase 1: Workflow Optimization (High Priority)

**Goal**: Reduce CI waste by 90%

**Tasks**:
1. Modify `.github/workflows/publish_python.yml`
2. Add commit message parsing logic
3. Implement conditional job execution
4. Test with various commit patterns

**Estimated Time**: 3 hours

**Success Criteria**:
- Commits without flags skip CI
- `--test` runs tests only (< 2 min)
- `--gen` regenerates binaries
- `--v X.Y.Z` publishes correctly

### Phase 2: Test Infrastructure (High Priority)

**Goal**: Create logging and test framework

**Tasks**:
1. Create `tests/utils/common.py` with TestLogger
2. Add test vectors (KAT) from NIST/RFC sources
3. Create directory structure for test modules
4. Implement test runner in `tests/utils/__init__.py`

**Estimated Time**: 4 hours

**Success Criteria**:
- TestLogger writes to correct subdirectories
- Logs match binary structure
- Test runner discovers all modules
- Summary log aggregates results

### Phase 3: Hash Tests (Medium Priority)

**Goal**: Test all 29 hash algorithms across 5 categories

**Tasks**:
1. `tests/utils/hash/test_primitive_fast.py` (6 algos)
2. `tests/utils/hash/test_primitive_memory_hard.py` (3 algos)
3. `tests/utils/hash/test_primitive_sponge_xof.py` (7 algos)
4. `tests/utils/hash/test_legacy_alive.py` (6 algos)
5. `tests/utils/hash/test_legacy_unsafe.py` (7 algos)

**Estimated Time**: 10 hours (2 hours per module)

**Success Criteria**:
- All 29 algorithms tested
- KAT vectors verified
- Determinism checked
- Collision resistance validated

### Phase 4: Core Tests (Medium Priority)

**Goal**: Test all 32 core cipher/ECC/MAC algorithms

**Tasks**:
1. `tests/utils/core/test_aes_modes.py` (9 modes)
2. `tests/utils/core/test_aes_aead.py` (7 modes)
3. `tests/utils/core/test_stream_aead.py` (1 algo)
4. `tests/utils/core/test_ecc.py` (6 curves)
5. `tests/utils/core/test_macs.py` (9 MACs)

**Estimated Time**: 12 hours

**Success Criteria**:
- Encrypt → Decrypt roundtrips work
- Sign → Verify cycles work
- ECDH produces matching shared secrets
- AEAD authentication works
- MAC verification works

### Phase 5: PQC Tests (Low Priority)

**Goal**: Test all 35 PQC algorithms

**Tasks**:
1. `tests/utils/pqc/test_kem_lattice.py` (6 algos)
2. `tests/utils/pqc/test_kem_code_based.py` (10 algos)
3. `tests/utils/pqc/test_sign_lattice.py` (7 algos)
4. `tests/utils/pqc/test_sign_hash_based.py` (12 algos)

**Estimated Time**: 14 hours

**Success Criteria**:
- KEM: Encapsulate → Decapsulate produces matching shared secrets
- Sign: Sign → Verify(valid) returns True
- Sign: Verify(invalid) returns False
- All key sizes correct

### Phase 6: DHCM/PoW Tests (Low Priority)

**Goal**: Test DHCM (5) and PoW (15) configurations

**Tasks**:
1. DHCM tests (5 hash categories)
2. PoW client tests (5 categories)
3. PoW server tests (5 categories)
4. PoW combined tests (5 categories)

**Estimated Time**: 8 hours

**Success Criteria**:
- DHCM calculations produce expected trials
- PoW client solves challenges
- PoW server verifies solutions
- Different difficulties tested

### Phase 7: Remaining Tests (Low Priority)

**Goal**: Test KDF, Encoding, Root operations

**Tasks**:
1. KDF tests (3 modules)
2. Encoding tests (3 modules)
3. Root tests (2 modules)

**Estimated Time**: 6 hours

**Success Criteria**:
- KDF derives correct lengths
- Encoding roundtrips work
- DRBG seeding works
- UDBF set/clear works

### Phase 8: CI Integration & Testing (High Priority)

**Goal**: Ensure tests run on all platforms

**Tasks**:
1. Update workflow to use new test structure
2. Add log artifact upload
3. Test on Ubuntu, macOS, Windows
4. Verify log structure correctness

**Estimated Time**: 4 hours

**Success Criteria**:
- Tests pass on all 3 platforms
- Logs uploaded as artifacts
- Log structure matches binary structure
- No encoding issues

### Phase 9: Documentation (Medium Priority)

**Goal**: Document the new system

**Tasks**:
1. Update README with testing approach
2. Add examples of running specific test modules
3. Document log structure
4. Add workflow flag usage guide

**Estimated Time**: 3 hours

**Success Criteria**:
- Clear README section on testing
- Examples for common workflows
- Log structure documented
- Flag combinations explained

---

## Part G: Timeline Estimate

| Phase | Description | Hours | Priority | Dependencies |
|-------|-------------|-------|----------|--------------|
| 1 | Workflow Optimization | 3 | High | None |
| 2 | Test Infrastructure | 4 | High | None |
| 3 | Hash Tests | 10 | Medium | Phase 2 |
| 4 | Core Tests | 12 | Medium | Phase 2 |
| 5 | PQC Tests | 14 | Low | Phase 2 |
| 6 | DHCM/PoW Tests | 8 | Low | Phase 2, 3 |
| 7 | KDF/Encoding/Root | 6 | Low | Phase 2 |
| 8 | CI Integration | 4 | High | Phase 1, 2 |
| 9 | Documentation | 3 | Medium | All phases |
| **TOTAL** | | **64 hours** | | |

**Suggested Execution Order**:
1. **Week 1** (High Priority): Phase 1, 2, 8 (11 hours) - Get workflow + infrastructure + CI working
2. **Week 2** (Core Testing): Phase 3, 4 (22 hours) - Hash + Core tests (most commonly used)
3. **Week 3** (Advanced): Phase 5, 6 (22 hours) - PQC + DHCM/PoW
4. **Week 4** (Completion): Phase 7, 9 (9 hours) - Remaining tests + docs

---

## Part H: Expected Outcomes

### Before (Current State)

```bash
$ python tests/test_all.py
Testing imports...
  nextssl.__version__ = 0.0.9
  [PASS] All modules imported successfully

Testing hash algorithms...
  HashAlgorithm count = 16
  [PASS] Verified 16 hash algorithms
...

Test Results: 13 passed, 0 failed out of 13
[SUCCESS] All tests passed!
```

**Issues**:
- Only structure validation (enums exist, classes callable)
- No actual crypto operations
- No logging to files
- No test vectors
- Can't debug failures

### After (New Implementation)

```bash
$ python tests/test_all.py

======================================================================
Running: hash/test_primitive_fast
======================================================================

======================================================================
  Primitive Fast Hash - Enum Validation
======================================================================
[PASS] SHA-256 structure                             size=32  value=1
[PASS] SHA-512 structure                             size=64  value=3
[PASS] BLAKE2b structure                             size=64  value=10
[PASS] BLAKE2s structure                             size=32  value=11
[PASS] BLAKE3 structure                              size=32  value=12

======================================================================
  Primitive Fast Hash - Known Answer Tests (KAT)
======================================================================
       SHA256(3 bytes): ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
[PASS] SHA256 KAT                                    input_len=3
       SHA256(0 bytes): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
[PASS] SHA256 KAT                                    input_len=0
       SHA512(3 bytes): ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9e...
[PASS] SHA512 KAT                                    input_len=3

======================================================================
  Primitive Fast Hash - Determinism
======================================================================
[PASS] SHA-256 determinism                           matches=True
[PASS] SHA-512 determinism                           matches=True
[PASS] BLAKE2b determinism                           matches=True

======================================================================
  Primitive Fast Hash - Collision Resistance
======================================================================
[PASS] SHA-256 collision                             different=True
[PASS] SHA-512 collision                             different=True

======================================================================
SUMMARY
======================================================================
Passed:  24
Failed:  0
Total:   24
Status:  PASS
======================================================================

... (tests continue for all modules) ...

======================================================================
NextSSL Test Suite - Overall Summary
2026-02-26 15:00:00 UTC
======================================================================

hash/primitive_fast          24/24     PASS
hash/primitive_memory_hard   15/15     PASS
hash/primitive_sponge_xof    28/28     PASS
hash/legacy_alive            24/24     PASS
hash/legacy_unsafe           28/28     PASS
core/aes_modes               54/54     PASS
core/aes_aead                42/42     PASS
core/stream_aead             6/6       PASS
core/ecc                     36/36     PASS
core/macs                    45/45     PASS
pqc/kem_lattice              36/36     PASS
pqc/kem_code_based           60/60     PASS
pqc/sign_lattice             42/42     PASS
pqc/sign_hash_based          72/72     PASS
dhcm/*                       25/25     PASS
pow/*                        75/75     PASS
kdf/*                        15/15     PASS
encoding/*                   15/15     PASS
root/*                       10/10     PASS
----------------------------------------------------------------------
TOTAL                        636/636   PASS
======================================================================

[INFO] Logs written to: logs/test/
[INFO] Summary log: logs/test/summary.log

Exit code: 0
```

**Benefits**:
- ✅ ~636 functional tests (vs 13 structural checks)
- ✅ All crypto operations tested (encrypt/decrypt, sign/verify, etc.)
- ✅ Detailed logs in `logs/test/` (mirroring binary structure)
- ✅ Test vectors verified against NIST/RFC standards
- ✅ Easy debugging with hex data output
- ✅ Per-module and overall summaries
- ✅ Clear pass/fail reporting
- ✅ Log structure matches binary/test organization

---

## Part I: Questions for Review

1. **Does the corrected algorithm categorization match the actual binary structure?**
   - Hash: 5 categories (primitive_fast, primitive_memory_hard, primitive_sponge_xof, legacy_alive, legacy_unsafe)
   - Core: 5 groups (aes_modes, aes_aead, stream_aead, ecc, macs)
   - PQC: 4 groups (kem_lattice, kem_code_based, sign_lattice, sign_hash_based)
   - DHCM: 5 categories (same as hash)
   - PoW: 15 configs (5 categories × 3 roles)

2. **Is the log directory structure correct?**
   - `logs/bin/` for binary generation (matching `bin/` structure)
   - `logs/test/` for Python tests (matching test module structure)

3. **Should implementation priority change?**
   - Current: Workflow → Infrastructure → Hash → Core → PQC → DHCM/PoW → KDF/Encoding/Root
   - Alternative: Infrastructure → Hash → Workflow → Core → ...

4. **Do test module names match expectations?**
   - E.g., `hash/test_primitive_fast.py` instead of just `test_hash.py`

5. **Should we use the test vectors from `script/test/main/*.py` files?**
   - They already have working KAT tests we can extract

6. **Any other requirements or changes needed?**

---

## Part J: Next Actions

**Please confirm**:
1. ✅ Algorithm categorization is correct
2. ✅ Log structure matches binary organization
3. ✅ Test priority order is acceptable
4. ✅ Ready to start implementation

**Then I will**:
1. Start with Phase 1 (Workflow Optimization)
2. Move to Phase 2 (Test Infrastructure)
3. Begin Phase 3 (Hash Tests) as proof of concept

**Or specify different priorities!**
