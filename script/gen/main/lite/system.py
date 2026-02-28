"""
Lite Variant - Layer 4 (Primary) - Unified System Build
Generates: system_lite.dll (~500KB)

This generator creates the unified lite API that combines all 9 core algorithms:
- Hash: SHA-256, SHA-512, BLAKE3
- AEAD: AES-256-GCM, ChaCha20-Poly1305
- KDF: HKDF, Argon2id
- Key Exchange: X25519, Kyber1024
- Signatures: Ed25519, Dilithium5
- PoW: SHA-256 based

Output: bin/<platform>/system_lite.dll
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import Config, Logger, Builder


def build(builder: Builder):
    """Build system_lite.dll with all 9 core lite algorithms."""
    src_dir = builder.config.src_dir
    sources = set()

    def add_sources(paths, recursive=True):
        """Helper to add sources and deduplicate."""
        for p in builder.get_sources(paths, recursive=recursive):
            sources.add(os.path.normpath(p))

    # Hash algorithms (SHA-256, SHA-512, BLAKE3)
    add_sources([
        os.path.join(src_dir, 'primitives/hash/fast/sha256/'),
        os.path.join(src_dir, 'primitives/hash/fast/sha512/'),
        os.path.join(src_dir, 'primitives/hash/fast/blake3/'),
    ], recursive=True)

    # AEAD algorithms (AES-GCM, ChaCha20-Poly1305) - include aes_ctr for CTR_cipher
    add_sources([
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ctr/'),
        os.path.join(src_dir, 'primitives/aead/aes_gcm/'),
        os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/'),
    ], recursive=True)

    # KDF/Password (HKDF, Argon2id) - Use PQCrypto/common for HKDF+HMAC
    # Add all Argon2id dependencies explicitly to avoid missing argon2_hash
    add_sources([
        os.path.join(src_dir, 'PQCrypto/common/hkdf/'),
        os.path.join(src_dir, 'primitives/hash/memory_hard/Argon2id/'),
        os.path.join(src_dir, 'primitives/hash/memory_hard/utils/'),
        os.path.join(src_dir, 'primitives/hash/memory_hard/blake2/'),
    ], recursive=True)
    # Sha2 and fips202 without keccak4x to avoid duplicates from common
    sha2_path = os.path.join(src_dir, 'PQCrypto/common/sha2.c')
    fips202_path = os.path.join(src_dir, 'PQCrypto/common/fips202.c')
    for p in [sha2_path, fips202_path]:
        if os.path.exists(p):
            sources.add(os.path.normpath(p))

    # Classical Key Exchange (X25519) - Use ed25519 implementation
    add_sources([
        os.path.join(src_dir, 'primitives/ecc/ed25519/'),
    ], recursive=True)

    # Classical Signatures (Ed25519)
    add_sources([
        os.path.join(src_dir, 'primitives/ecc/ed25519/'),
    ], recursive=True)

    # Post-Quantum Cryptography (ML-KEM-1024, ML-DSA-87)
    add_sources([
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-1024/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-87/'),
        os.path.join(src_dir, 'PQCrypto/common/'),
    ], recursive=True)

    # Lite variants use simplified implementations, not full PoW utils
    # PoW is handled in the lite wrapper directly

    # Add lite wrappers for all modules (so nextssl.c can call them)
    lite_wrappers = [
        os.path.join(src_dir, 'interfaces/main/lite/hash.c'),
        os.path.join(src_dir, 'interfaces/main/lite/aead.c'),
        os.path.join(src_dir, 'interfaces/main/lite/password.c'),
        os.path.join(src_dir, 'interfaces/main/lite/keyexchange.c'),
        os.path.join(src_dir, 'interfaces/main/lite/signature.c'),
        os.path.join(src_dir, 'interfaces/main/lite/pqc.c'),
        os.path.join(src_dir, 'interfaces/main/lite/pow.c'),
    ]
    for wrapper in lite_wrappers:
        if os.path.exists(wrapper):
            sources.add(os.path.normpath(wrapper))

    # Add essential utility wrappers
    utility_wrappers = [
        os.path.join(src_dir, 'utils/base_encryption.c'),  # AES wrapper
        os.path.join(src_dir, 'utils/pqc_main.c'),          # PQC wrapper
    ]
    
    for wrapper in utility_wrappers:
        if os.path.exists(wrapper):
            sources.add(os.path.normpath(wrapper))

    # Add Layer 4 primary wrapper (if exists)
    primary_wrapper = os.path.join(src_dir, 'interfaces/primary/lite/nextssl.c')
    if os.path.exists(primary_wrapper):
        sources.add(os.path.normpath(primary_wrapper))

    # Convert set to list for builder
    sources_list = list(sources)

    # Include directories for PQCrypto headers
    includes = [
        os.path.join(src_dir, 'PQCrypto', 'common'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem', 'ml-kem-1024', 'clean'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_sign', 'ml-dsa-87', 'clean')
    ]

    # Build with pthread support
    return builder.build_target(
        'system',
        sources_list,
        extra_libs=['-lpthread'],
        includes=includes,
        output_subdir='primary/lite'  # Primary layer lite variant
    )


if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('system_lite', 'build')) as logger:
        builder = Builder(config, logger)
        success = build(builder)
        sys.exit(0 if success else 1)
