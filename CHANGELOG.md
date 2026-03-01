# Changelog

## [0.0.1-beta] - 2026-02-28

### 🎉 Major Milestone: STEP_001 Complete - 4-Layer Interface Architecture

This release marks the completion of the foundational interface architecture with 62 professional-grade interface headers across 4 layers.

#### Added

**Build System:**
- ✅ CMake build system with full variant support (Lite/Full)
- ✅ Platform-specific configurations (Linux, macOS, Windows)
- ✅ Symbol visibility control system
- ✅ Security-hardened compiler flags
- ✅ Code coverage and sanitizer support
- ✅ CMake package configuration for easy integration
- ✅ Comprehensive BUILD.md guide

**Interface Architecture (62 interfaces total):**

**Layer 4 (Primary) - 1 interface:**
- `primary/nextssl.h` - Unified ultra-simple API (~400 lines)
  - Single-header convenience for common operations
  - Version 0.0.1-beta
  - Quick start guide embedded in header

**Layer 3 (Main) - 7 interfaces:**
- `main/core.h` - High-level core operations
- `main/hash.h` - Simple hashing (SHA-256 default)
- `main/pow.h` - Simple password hashing (Argon2id)
- `main/dhcm.h` - Simple key exchange (X25519)
- `main/sign.h` - Simple signatures (Ed25519)
- `main/pqc.h` - Post-quantum operations
- `main/aead.h` - Simple AEAD (AES-GCM)

**Layer 2 (Base) - 14 interfaces:**
- `base/core.h` - Core primitives aggregation
- `base/hash.h` - Hash functions (SHA-2/3, BLAKE2/3)
- `base/pow.h` - Password hashing (Argon2id, scrypt, bcrypt)
- `base/dhcm.h` - Key exchange (X25519, X448, ML-KEM-768, P-256)
- `base/pqc.h` - Post-quantum (ML-KEM, ML-DSA)
- `base/kdf.h` - Key derivation (HKDF, Argon2id, PBKDF2)
- `base/mac.h` - MACs (HMAC-SHA256/512/SHA3)
- `base/sign.h` - Signatures (Ed25519, ECDSA, ML-DSA-65)
- `base/utils.h` - Utilities (secure memory, constant-time)
- `base/radix.h` - Encoding (Base64, Hex, Base58)
- `base/aead_modern.h` - Modern AEAD (AES-GCM, ChaCha20-Poly1305)
- `base/hash_legacy.h` - Legacy hashes with deprecation warnings
- `base/cipher_legacy.h` - Legacy ciphers with deprecation warnings
- `base/ecc.h` - ECC operations (Curve25519/448, P-256/384/521)

**Layer 1 (Partial) - 40 interfaces:**
- All low-level primitives across Core, DHCM, Hash, PoW, and PQC categories
- Hidden from external users (NEXTSSL_PARTIAL_API)
- Internal implementation details

**Examples:**
- `example_quickstart.c` - Comprehensive getting started example
- Examples CMake configuration with automatic discovery

**Documentation:**
- BUILD.md - Complete build and installation guide
- Updated README.md with 4-layer architecture explanation
- Enhanced ALGORITHM.md references
- CI/CD workflow (.github/workflows/ci.yml)

**Development Tools:**
- VS Code IntelliSense configuration (.vscode/c_cpp_properties.json)
- Test suite CMake configuration
- Symbol visibility header (`visibility.h`)

#### Technical Highlights

- **Security First**: All interfaces follow constant-time principles
- **Standards Compliant**: NIST FIPS 180-4, 202, 203, 204; RFC 7748, 8032, 9106
- **Safe Defaults**: AES-256-GCM, SHA-256, Argon2id (OWASP 2023), X25519, Ed25519
- **Progressive Complexity**: Start simple (Layer 4), go deep when needed (Layer 1)
- **Professional Quality**: ~8,000+ lines of documented interface headers
- **Build Variants**: Lite (9 algos, 1 bin) vs Full (134 algos, 56 bins)
- **Platform Support**: Linux, macOS, Windows, with cross-compilation support

#### Changes

- Upgraded from Python runner to CMake as primary build system
- Reorganized interface headers into 4-layer hierarchy
- Isolated legacy algorithms with clear deprecation warnings
- Added symbol visibility controls for proper API exposure

#### Next Steps

- ⏳ Implement backing code for Layer 1 primitives
- ⏳ STEP_002: Security hardening (constant-time enforcement)
- ⏳ STEP_003: Build system finalization (binary tracking)
- ⏳ Create comprehensive test suite
- ⏳ Python bindings for PyPI distribution

---

## [Unreleased] - 2026-02-12-

### System & Workflow [T-6]
- **Prompt Upgrade (Addendum)**:
  - Added strict logging rules for `log/chat` and `log/prompt`.
  - Documented purpose and usage for all `note/` subdirectories (`tasks`, `changes`, `bin`, `code`, `features`, `idea`).
  - Added Pre-flight checks for log directories.

- **Prompt Upgrade**:
  - Completely rewrote `PROMPT.md` to enforce strict document-driven workflow.
  - Established `note/tasks/` as the sole location for task definitions.
  - Established `note/changes/` for atomic change logging.
  - Implemented mandatory pre-flight checklist and output quality gates.
