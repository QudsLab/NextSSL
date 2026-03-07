import os
from script.core import Builder

def build(builder: Builder):
    src_dir = builder.config.src_dir
    sources = set()

    def add_sources(paths, recursive=True):
        for p in builder.get_sources(paths, recursive=recursive):
            sources.add(os.path.normpath(p))

    add_sources([
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
        os.path.join(src_dir, 'legacy/alive/aes_ecb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cbc/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cfb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ofb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ctr/'),
        os.path.join(src_dir, 'primitives/cipher/aes_xts/'),
        os.path.join(src_dir, 'primitives/cipher/aes_kw/'),
        os.path.join(src_dir, 'primitives/cipher/aes_fpe/'),
        os.path.join(src_dir, 'primitives/aead/aes_gcm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ccm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ocb/'),
        os.path.join(src_dir, 'primitives/aead/aes_eax/'),
        os.path.join(src_dir, 'primitives/aead/aes_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_gcm_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_poly1305/'),
        os.path.join(src_dir, 'primitives/mac/aes_cmac/'),
        os.path.join(src_dir, 'primitives/mac/siphash/'),
        os.path.join(src_dir, 'PQCrypto/common/hkdf/'),
        os.path.join(src_dir, 'primitives/ecc/ed25519/'),
        os.path.join(src_dir, 'primitives/ecc/curve448/'),
        os.path.join(src_dir, 'primitives/ecc/elligator2/'),
        os.path.join(src_dir, 'primitives/ecc/ristretto255/'),
    ], recursive=True)

    sources.add(os.path.normpath(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/chacha20_poly1305.c')))
    sources.add(os.path.normpath(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/monocypher.c')))
    sources.add(os.path.normpath(os.path.join(src_dir, 'PQCrypto/common/sha2.c')))
    sources.add(os.path.normpath(os.path.join(src_dir, 'PQCrypto/common/fips202.c')))
    sources.add(os.path.normpath(os.path.join(src_dir, 'primitives/hash/sponge_xof/shake/shake.c')))
    sources.add(os.path.normpath(os.path.join(src_dir, 'utils/drbg/drbg.c')))

    wrapper = os.path.join(src_dir, 'utils', 'base_encryption.c')
    if os.path.exists(wrapper):
        sources.add(os.path.normpath(wrapper))

    add_sources([
        os.path.join(src_dir, 'primitives', 'hash'),
        os.path.join(src_dir, 'legacy'),
        os.path.join(src_dir, 'primitives', 'cipher', 'aes_core')
    ], recursive=True)

    add_sources([os.path.join(src_dir, 'utils', 'hash')], recursive=False)

    add_sources([
        os.path.join(src_dir, 'DHCM/core/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_fast/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_memory_hard/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_sponge_xof/'),
        os.path.join(src_dir, 'DHCM/adapters/legacy_alive/'),
        os.path.join(src_dir, 'DHCM/adapters/legacy_unsafe/'),
        os.path.join(src_dir, 'DHCM/utils/'),
    ], recursive=True)

    add_sources([
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/server/'),
        os.path.join(src_dir, 'PoW/client/')
    ], recursive=True)
    adapter_dirs = [
        os.path.join(src_dir, 'PoW/adapters/primitive_fast/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_memory_hard/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_sponge_xof/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_alive/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_unsafe/')
    ]
    for d in adapter_dirs:
        for p in builder.get_sources([d], recursive=True):
            if not p.endswith('dispatcher.c'):
                sources.add(os.path.normpath(p))
    sources.add(os.path.normpath(os.path.join(src_dir, 'PoW/adapters/dispatcher_main.c')))
    add_sources([os.path.join(src_dir, 'utils/radix/')], recursive=False)  # all radix encoders

    add_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast'),
        os.path.join(src_dir, 'primitives', 'hash', 'sponge_xof'),
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard'),
        os.path.join(src_dir, 'legacy/alive/'),
        os.path.join(src_dir, 'legacy/unsafe/')
    ], recursive=True)

    hash_wrapper = os.path.join(src_dir, 'utils', 'hash', 'primitive_memory_hard.c')
    if os.path.exists(hash_wrapper):
        sources.add(os.path.normpath(hash_wrapper))

    add_sources([os.path.join(src_dir, 'primitives/cipher/aes_core/')], recursive=True)

    pow_wrapper = os.path.join(src_dir, 'utils', 'pow', 'combined', 'main.c')
    if os.path.exists(pow_wrapper):
        sources.add(os.path.normpath(pow_wrapper))

    add_sources([
        os.path.join(src_dir, 'PQCrypto/crypto_kem/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/'),
        os.path.join(src_dir, 'PQCrypto/common/'),
    ], recursive=True)

    add_sources([
        os.path.join(src_dir, 'utils/pqc'),
    ], recursive=True)

    pqc_wrapper = os.path.join(src_dir, 'utils', 'pqc_main.c')
    if os.path.exists(pqc_wrapper):
        sources.add(os.path.normpath(pqc_wrapper))

    # Add Layer 4 primary wrapper (full variant)
    primary_wrapper = os.path.join(src_dir, 'interfaces/primary/full/nextssl.c')
    if os.path.exists(primary_wrapper):
        sources.add(os.path.normpath(primary_wrapper))

    # Add root/ explicit-algorithm interface (anchor stub)
    root_wrapper = os.path.join(src_dir, 'interfaces/primary/full/root/nextssl_root.c')
    if os.path.exists(root_wrapper):
        sources.add(os.path.normpath(root_wrapper))

    # Add root/ sub-group implementations (tree structure)
    root_sub_files = [
        'interfaces/primary/full/root/hash/root_hash.c',
        'interfaces/primary/full/root/core/root_aead.c',
        'interfaces/primary/full/root/core/root_cipher.c',
        'interfaces/primary/full/root/core/root_ecc.c',
        'interfaces/primary/full/root/core/root_mac.c',
        'interfaces/primary/full/root/pqc/root_pqc_kem.c',
        'interfaces/primary/full/root/pqc/root_pqc_sign.c',
        'interfaces/primary/full/root/legacy/root_legacy.c',
        'interfaces/primary/full/root/radix/root_radix.c',
        'interfaces/primary/full/root/pow/root_pow.c',
    ]
    for rsf in root_sub_files:
        p = os.path.join(src_dir, rsf)
        if os.path.exists(p):
            sources.add(os.path.normpath(p))

    # Add profile-based configuration system
    config_sources = [
        os.path.join(src_dir, 'config/config.c'),
        os.path.join(src_dir, 'config/profiles/profiles_common.c'),
    ]
    for cs in config_sources:
        if os.path.exists(cs):
            sources.add(os.path.normpath(cs))

    includes = [
        os.path.join(src_dir, 'primitives/cipher/aes_core'),
        os.path.join(src_dir, 'primitives/cipher'),
        os.path.join(src_dir, 'primitives/aead'),
        os.path.join(src_dir, 'primitives/mac'),
        os.path.join(src_dir, 'primitives/aead/chacha20_poly1305'),
        os.path.join(src_dir, 'primitives/ecc/ed25519'),
        os.path.join(src_dir, 'primitives/ecc/curve448'),
        os.path.join(src_dir, 'primitives/ecc/elligator2'),
        os.path.join(src_dir, 'primitives/ecc/ristretto255'),
        os.path.join(src_dir, 'PQCrypto/common'),
        os.path.join(src_dir, 'primitives/hash/sponge_xof/shake'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign'),
        os.path.join(src_dir, 'PQCrypto/common'),
        os.path.join(src_dir, 'utils/pqc'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-768/clean'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-65/clean'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-87/clean'),
        os.path.join(src_dir, 'interfaces/primary/full/root'),
        src_dir,
    ]

    macros = [
        ('AES___', '128'),
        ('FF_X', '1'),
        ('HAVE_ED448', '1'),
        ('HAVE_CURVE448', '1'),
        'DHCM_VERSION_MAJOR=1',
        'DHCM_VERSION_MINOR=0',
        'DHCM_ENABLE_PRIMITIVE_FAST',
        'DHCM_ENABLE_PRIMITIVE_MEMORY_HARD',
        'DHCM_ENABLE_PRIMITIVE_SPONGE_XOF',
        'DHCM_ENABLE_LEGACY_ALIVE',
        'DHCM_ENABLE_LEGACY_UNSAFE',
        'POW_ENABLE_SERVER',
        'POW_ENABLE_CLIENT',
        'POW_ENABLE_PRIMITIVE_FAST',
        'POW_ENABLE_PRIMITIVE_MEMORY_HARD',
        'POW_ENABLE_PRIMITIVE_SPONGE_XOF',
        'POW_ENABLE_LEGACY_ALIVE',
        'POW_ENABLE_LEGACY_UNSAFE',
        'POW_NO_GENERIC_API',
        'ENABLE_ML_KEM',
        'ENABLE_HQC',
        'ENABLE_MCELIECE',
        'ENABLE_ML_DSA',
        'ENABLE_FALCON',
        'ENABLE_SPHINCS',
        'NEXTSSL_BUILDING_DLL',
    ]

    extra_libs = ['-lpthread']
    if builder.config.lib_ext == '.dll':   # bcrypt is Windows-only
        extra_libs.append('-lbcrypt')

    _WASM_SYSTEM_EXPORTS = [
        # High-level API
        'nextssl_init', 'nextssl_init_custom', 'nextssl_cleanup',
        'nextssl_encrypt', 'nextssl_decrypt', 'nextssl_hash',
        'nextssl_security_level', 'nextssl_sha256',
        # Root layer
        'nextssl_root_hash_sha256', 'nextssl_root_hash_sha512',
        'nextssl_root_hash_sha3_256', 'nextssl_root_hash_blake3',
        'nextssl_root_hash_argon2id',
        'nextssl_root_ecc_ed25519_keygen', 'nextssl_root_ecc_ed25519_sign',
        'nextssl_root_ecc_ed25519_verify',
        'nextssl_root_ecc_x25519_keygen', 'nextssl_root_ecc_x25519_exchange',
        'nextssl_root_pqc_kem_mlkem768_keygen',
        'nextssl_root_pqc_kem_mlkem768_encaps',
        'nextssl_root_pqc_kem_mlkem768_decaps',
        'nextssl_root_pqc_sign_mldsa65_keygen',
        'nextssl_root_pqc_sign_mldsa65_sign', 'nextssl_root_pqc_sign_mldsa65_verify',
        'nextssl_root_pqc_sign_mldsa87_keygen',
        'nextssl_root_pqc_sign_mldsa87_sign', 'nextssl_root_pqc_sign_mldsa87_verify',
        'nextssl_root_pow_server_challenge', 'nextssl_root_pow_server_verify',
        'nextssl_root_pow_client_solve',
        'nextssl_root_legacy_alive_md5', 'nextssl_root_legacy_alive_sha1',
        'nextssl_dhcm_expected_trials',
        # Compat
        'AES_CBC_encrypt', 'pqc_mlkem512_keypair',
    ]

    return builder.build_target(
        'main',
        list(sources),
        includes=includes,
        macros=macros,
        remove_macros=['EXCLUDE_SPHINCS'],
        extra_libs=extra_libs,
        output_subdir='primary',
        wasm_exports=_WASM_SYSTEM_EXPORTS
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('main', 'system')) as logger:
        build(Builder(config, logger))
