# Changelog

## [Unreleased] - 2026-02-07-

### CI/CD & Testing
- **Compiler Script**: Added `script/compiler.py` to automate compilation of the PQC library into a shared library (`pqc_lib.dll`).
- **Test Suite**: Added `test/pqc_main_test.py` to verify PQC functionality (KEM, Sign, Derandomization) using the compiled library.
- **Bug Fixes**:
  - Fixed compilation errors in `hkdf.c` (incorrect parameter order).
  - Fixed `undefined reference` linking errors by correcting include paths and headers in `pqc_main.c`.

### Refactoring & Architecture
- **PQC Restructuring**:
  - Replaced legacy `src/PQC` structure with a modular `src/PQCrypto` directory based on the PQClean standard.
  - Organized algorithms into `crypto_kem` (Key Encapsulation) and `crypto_sign` (Signatures).
  - Consolidated shared PQC utilities into `src/PQCrypto/common`.
- **Modular AES**:
  - Split monolithic AES implementation into `src/BaseEncryption/AES_*` with separate headers/sources for each mode (GCM, CBC, CTR, etc.).
- **Modular Argon2**:
  - Refactored Argon2 into `src/AdvanceHash/Argon2_*` variants (Argon2d, Argon2i, Argon2id) with a unified C exporter `src/ahs_argon.c`.

### New Features
- **Dynamic Key Insertion (Derandomization)**:
  - Added `_derand` API variants for all supported PQC algorithms to allow manual seed injection:
    - `pqc_mlkem768_keypair_derand` / `encaps_derand`
    - `pqc_mldsa65_keypair_derand` / `sign_derand`
    - `pqc_hqc128_keypair_derand` / `encaps_derand`
- **Core Cryptography**:
  - **HMAC-DRBG**: Implemented NIST SP 800-90A compliant Deterministic Random Bit Generator in `src/PQCrypto/common/drbg`.
  - **HKDF**: Added HMAC-based Extract-and-Expand Key Derivation Function (SHA-256) in `src/PQCrypto/common/hkdf`.
  - **Unified Entry Point**: Created `src/pqc_main.c` as the central API for PQC operations, managing global DRBG state and algorithm dispatch.

### Removed
- Removed obsolete `src/PQC` and `src/common` directories to prevent conflicts.
- Removed legacy `ahs_argon.s` assembly stub in favor of a proper C implementation.
