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
    sources.add(os.path.normpath(os.path.join(src_dir, 'utils/radix/base64.c')))

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
        src_dir,
    ]

    macros = [
        ('AES___', '128'),
        ('FF_X', '1'),
        ('HAVE_ED448', '1'),
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
        'ENABLE_SPHINCS'
    ]

    return builder.build_target(
        'system',
        list(sources),
        includes=includes,
        macros=macros,
        remove_macros=['EXCLUDE_SPHINCS'],
        extra_libs=['-lpthread'],
        output_subdir='primary/full'
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('main', 'system')) as logger:
        build(Builder(config, logger))
