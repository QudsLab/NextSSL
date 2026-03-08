"""
Lite Variant - Layer 4 (Primary) - Unified System Build
Generates: system_lite.dll (~500KB)

This generator creates the unified lite API that combines all 9 core algorithms
plus the explicit-algorithm root tree and the PoW subsystem (4 lite algorithms):
- Hash: SHA-256, SHA-512, BLAKE3
- AEAD: AES-256-GCM, ChaCha20-Poly1305
- KDF: HKDF, Argon2id
- Key Exchange: X25519, Kyber1024
- Signatures: Ed25519, Dilithium5
- PoW: SHA-256, SHA-512, BLAKE3, Argon2id (dispatcher_lite.c, 4 adapters)
- Root tree: nextssl_root_hash_*, nextssl_root_aead_*, nextssl_root_ecc_*,
             nextssl_root_pqc_kem_*, nextssl_root_pqc_sign_*, nextssl_root_pow_*

Output: bin/<platform>/system_lite.dll
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import Config, Logger, Builder

# Export list for the primary/system_lite binary.
# Defined at module level so probe files can import it directly.
_WASM_LITE_EXPORTS = [
    # High-level API
    'nextssl_init', 'nextssl_init_custom', 'nextssl_cleanup',
    'nextssl_hash', 'nextssl_encrypt', 'nextssl_decrypt',
    'nextssl_security_level',
    # Root hash (SHA-256, SHA-512, BLAKE3, Argon2id — no SHA3 in lite)
    'nextssl_root_hash_sha256', 'nextssl_root_hash_sha512',
    'nextssl_root_hash_blake3', 'nextssl_root_hash_argon2id',
    # Root ECC
    'nextssl_root_ecc_ed25519_keygen', 'nextssl_root_ecc_ed25519_sign',
    'nextssl_root_ecc_ed25519_verify',
    'nextssl_root_ecc_x25519_keygen', 'nextssl_root_ecc_x25519_exchange',
    # Root PQC KEM (ML-KEM-1024 in lite)
    'nextssl_root_pqc_kem_mlkem1024_keygen',
    'nextssl_root_pqc_kem_mlkem1024_encaps',
    'nextssl_root_pqc_kem_mlkem1024_decaps',
    # Root PQC Sign (ML-DSA-87 only in lite)
    'nextssl_root_pqc_sign_mldsa87_keygen',
    'nextssl_root_pqc_sign_mldsa87_sign',
    'nextssl_root_pqc_sign_mldsa87_verify',
    # Root PoW
    'nextssl_root_pow_server_challenge',
    'nextssl_root_pow_server_verify',
    'nextssl_root_pow_client_solve',
    # Memory allocation — required by Python wasmtime tests in script/web/
    'malloc', 'free',
]


def build(builder: Builder):
    """Build system_lite.dll with all 9 core lite algorithms."""
    src_dir = builder.config.src_dir
    sources = set()

    def add_sources(paths, recursive=True):
        """Helper to add sources and deduplicate."""
        for p in builder.get_sources(paths, recursive=recursive):
            sources.add(os.path.normpath(p))

    # Hash algorithms (SHA-256, SHA-512, BLAKE3, SHA3, BLAKE2b for base layer)
    add_sources([
        os.path.join(src_dir, 'primitives/hash/fast/sha256/'),
        os.path.join(src_dir, 'primitives/hash/fast/sha512/'),
        os.path.join(src_dir, 'primitives/hash/fast/blake3/'),
        os.path.join(src_dir, 'primitives/hash/fast/blake2b/'),
        os.path.join(src_dir, 'primitives/hash/sponge_xof/sha3/'),
        os.path.join(src_dir, 'primitives/hash/sponge_xof/shake/'),
    ], recursive=True)

    # AEAD algorithms (AES-GCM, ChaCha20-Poly1305) - include aes_ctr for CTR_cipher
    add_sources([
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ctr/'),
        os.path.join(src_dir, 'primitives/aead/aes_gcm/'),
        os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/'),
    ], recursive=True)

    # KDF/Password (HKDF, Argon2id) - Use PQCrypto/common for HKDF+HMAC
    add_sources([
        os.path.join(src_dir, 'PQCrypto/common/hkdf/'),
        os.path.join(src_dir, 'primitives/hash/memory_hard/Argon2id/'),
        os.path.join(src_dir, 'primitives/hash/memory_hard/utils/'),
        os.path.join(src_dir, 'primitives/hash/memory_hard/blake2/'),
    ], recursive=True)
    # sha2 and fips202 (needed by Argon2id)
    sha2_path = os.path.join(src_dir, 'PQCrypto/common/sha2.c')
    fips202_path = os.path.join(src_dir, 'PQCrypto/common/fips202.c')
    for p in [sha2_path, fips202_path]:
        if os.path.exists(p):
            sources.add(os.path.normpath(p))

    # Classical Key Exchange + Signatures (X25519, Ed25519 share same lib)
    # Also include curve448 and elligator2 needed by seed/keygen.c
    add_sources([
        os.path.join(src_dir, 'primitives/ecc/ed25519/'),
        os.path.join(src_dir, 'primitives/ecc/curve448/'),
        os.path.join(src_dir, 'primitives/ecc/elligator2/'),
        os.path.join(src_dir, 'primitives/ecc/ristretto255/'),
    ], recursive=True)

    # Post-Quantum Cryptography — all variants needed by seed/keygen.c
    add_sources([
        os.path.join(src_dir, 'PQCrypto/crypto_kem/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/'),
        os.path.join(src_dir, 'PQCrypto/common/'),
    ], recursive=True)

    # Add lite wrappers for modules NOT already in nextssl.c
    # NOTE: nextssl.c (primary/lite/nextssl.c) already implements nextssl_hash,
    #       nextssl_password_hash/verify, nextssl_pow_solve/verify directly.
    #       Only include the wrappers that nextssl.c delegates to.
    lite_wrappers = [
        os.path.join(src_dir, 'interfaces/main/lite/aead.c'),
        os.path.join(src_dir, 'interfaces/main/lite/keyexchange.c'),
        os.path.join(src_dir, 'interfaces/main/lite/signature.c'),
        os.path.join(src_dir, 'interfaces/main/lite/pqc.c'),
    ]
    for wrapper in lite_wrappers:
        if os.path.exists(wrapper):
            sources.add(os.path.normpath(wrapper))

    # Add PQC main wrapper
    pqc_wrapper = os.path.join(src_dir, 'PQCrypto/pqc_main.c')
    if os.path.exists(pqc_wrapper):
        sources.add(os.path.normpath(pqc_wrapper))

    # Full seed module (keygen.c uses wc_ed448, elligator2, and all PQC derand functions)
    add_sources([os.path.join(src_dir, 'seed/')], recursive=True)

    # Filter: PQCrypto/common/drbg conflicts with seed/drbg
    _drbg_excl = os.path.normpath(os.path.join(src_dir, 'PQCrypto', 'common', 'drbg'))
    sources = {s for s in sources if not s.startswith(_drbg_excl)}

    # Layer 2 base implementations (in excluded subdirs, must add explicitly)
    _core_base_files = [
        'interfaces/core/primitive/fast/hash.c',
        'interfaces/core/pow/pow.c',
    ]
    for _f in _core_base_files:
        _p = os.path.normpath(os.path.join(src_dir, _f))
        if os.path.exists(_p):
            sources.add(_p)

    # Add Layer 4 primary wrapper
    primary_wrapper = os.path.join(src_dir, 'interfaces/primary/lite/nextssl.c')
    if os.path.exists(primary_wrapper):
        sources.add(os.path.normpath(primary_wrapper))

    # Add root/ sub-module implementations
    root_sub_modules = [
        'interfaces/root/nextssl_root.c',
        'interfaces/root/hash/root_hash.c',
        'interfaces/root/core/root_aead.c',
        'interfaces/root/core/root_cipher.c',
        'interfaces/root/core/root_ecc.c',
        'interfaces/root/core/root_mac.c',
        'interfaces/root/pqc/root_pqc_kem.c',
        'interfaces/root/pqc/root_pqc_sign.c',
        'interfaces/root/pow/root_pow.c',
    ]
    for rm in root_sub_modules:
        p = os.path.normpath(os.path.join(src_dir, rm))
        if os.path.exists(p):
            sources.add(p)

    # PoW subsystem (needed by root_pow.c)
    add_sources([
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/server/'),
        os.path.join(src_dir, 'PoW/client/'),
    ], recursive=True)
    # PoW adapters (lite: only the 4 algorithms used by dispatcher_lite.c)
    pow_lite_adapters = [
        'PoW/adapters/primitive_fast/sha256.c',
        'PoW/adapters/primitive_fast/sha512.c',
        'PoW/adapters/primitive_fast/blake3.c',
        'PoW/adapters/primitive_memory_hard/argon2id.c',
        'PoW/adapters/dispatcher_lite.c',
    ]
    for _f in pow_lite_adapters:
        _p = os.path.normpath(os.path.join(src_dir, _f))
        if os.path.exists(_p):
            sources.add(_p)
    sources.add(os.path.normpath(os.path.join(src_dir, 'PoW/pow_api.c')))

    # DHCM wu functions needed by PoW adapters (standalone math, no DHCM core needed)
    dhcm_wu_files = [
        'DHCM/adapters/primitive_fast/sha256.c',
        'DHCM/adapters/primitive_fast/sha512.c',
        'DHCM/adapters/primitive_fast/blake3.c',
        'DHCM/adapters/primitive_memory_hard/argon2id.c',
    ]
    for _f in dhcm_wu_files:
        _p = os.path.normpath(os.path.join(src_dir, _f))
        if os.path.exists(_p):
            sources.add(_p)

    # Argon2i and Argon2d (needed by pow_api.c nextssl_argon2i/nextssl_argon2d wrappers)
    for _f in ['primitives/hash/memory_hard/Argon2i/argon2i.c',
               'primitives/hash/memory_hard/Argon2d/argon2d.c']:
        _p = os.path.normpath(os.path.join(src_dir, _f))
        if os.path.exists(_p):
            sources.add(_p)
    add_sources([os.path.join(src_dir, 'common/encoding/')], recursive=False)

    # NOTE: The full PoW subsystem (PoW/core, PoW/adapters, DHCM) is NOT included
    # in system_lite. PoW functionality is provided by the self-contained
    # root_pow.c implementation (SHA-256 token-based PoW, no external deps).

    # Add profile-based configuration system (config.c + profiles_common.c)
    config_sources = [
        os.path.join(src_dir, 'config/config.c'),
        os.path.join(src_dir, 'config/profiles/profiles_common.c'),
    ]
    for cs in config_sources:
        if os.path.exists(cs):
            sources.add(os.path.normpath(cs))

    # Include directories for PQCrypto and PoW headers
    includes = [
        os.path.join(src_dir, 'PQCrypto', 'common'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem', 'ml-kem-1024', 'clean'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_sign'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_sign', 'ml-dsa-87', 'clean'),
        os.path.join(src_dir, 'interfaces', 'root'),
        os.path.join(src_dir, 'primitives', 'cipher', 'aes_core'),
        os.path.join(src_dir, 'primitives', 'ecc', 'ed25519'),
        os.path.join(src_dir, 'primitives', 'ecc', 'curve448'),
        os.path.join(src_dir, 'primitives', 'ecc', 'elligator2'),
        os.path.join(src_dir, 'primitives', 'ecc', 'ristretto255'),
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard', 'utils'),
        os.path.join(src_dir, 'seed'),
        src_dir,
    ]

    # Build with pthread support
    # NEXTSSL_BUILDING_DLL ensures NEXTSSL_API expands to __declspec(dllexport) on Windows
    # NEXTSSL_BUILD_LITE restricts profile enum to 3 profiles (MODERN, COMPLIANCE, PQC)
    extra_libs = ['-lpthread']
    if builder.config.lib_ext == '.dll':   # bcrypt is Windows-only
        extra_libs.append('-lbcrypt')

    return builder.build_target(
        'main_lite',
        list(sources),
        extra_libs=extra_libs,
        includes=includes,
        output_subdir='primary',
        macros=[
            ('AES___', '128'),
            ('FF_X', '1'),
            ('HAVE_ED448', '1'),
            ('HAVE_CURVE448', '1'),
            'ENABLE_ML_KEM',
            'ENABLE_HQC',
            'ENABLE_MCELIECE',
            'ENABLE_ML_DSA',
            'ENABLE_FALCON',
            'ENABLE_SPHINCS',
            'POW_ENABLE_SERVER',
            'POW_ENABLE_CLIENT',
            'POW_ENABLE_PRIMITIVE_FAST',
            'POW_ENABLE_PRIMITIVE_MEMORY_HARD',
            'POW_NO_GENERIC_API',
            'NEXTSSL_BUILDING_DLL',
            'NEXTSSL_BUILD_LITE=1',
        ],
        remove_macros=['EXCLUDE_SPHINCS'],
        wasm_exports=_WASM_LITE_EXPORTS,
    )


if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('system_lite', 'build')) as logger:
        builder = Builder(config, logger)
        success = build(builder)
        sys.exit(0 if success else 1)
