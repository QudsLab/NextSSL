import os
from script.core import Builder

def build(builder: Builder):
    """Build core.dll (Main Tier) - Complete Classic Crypto Suite."""
    src_dir = builder.config.src_dir
    
    # Combined sources from ALL core categories
    sources = builder.get_sources([
        # Cipher
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
        os.path.join(src_dir, 'legacy/alive/aes_ecb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cbc/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cfb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ofb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ctr/'),
        os.path.join(src_dir, 'primitives/cipher/aes_xts/'),
        os.path.join(src_dir, 'primitives/cipher/aes_kw/'),
        os.path.join(src_dir, 'primitives/cipher/aes_fpe/'),
        
        # AEAD
        os.path.join(src_dir, 'primitives/aead/aes_gcm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ccm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ocb/'),
        os.path.join(src_dir, 'primitives/aead/aes_eax/'),
        os.path.join(src_dir, 'primitives/aead/aes_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_gcm_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_poly1305/'),
        # os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/'), # Handled below to exclude optional
        
        # MAC
        os.path.join(src_dir, 'primitives/mac/aes_cmac/'),
        os.path.join(src_dir, 'primitives/mac/siphash/'),
        os.path.join(src_dir, 'PQCrypto/common/hkdf/'),
        
        # ECC
        os.path.join(src_dir, 'primitives/ecc/ed25519/'),
        os.path.join(src_dir, 'primitives/ecc/curve448/'),
        os.path.join(src_dir, 'primitives/ecc/elligator2/'),
        os.path.join(src_dir, 'primitives/ecc/ristretto255/'),
    ], recursive=True)
    
    # Add individual files
    sources.append(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/chacha20_poly1305.c'))
    sources.append(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/monocypher.c'))
    
    sources.append(os.path.join(src_dir, 'PQCrypto/common/sha2.c'))
    sources.append(os.path.join(src_dir, 'PQCrypto/common/fips202.c')) # SHA3/SHAKE for HKDF
    sources.append(os.path.join(src_dir, 'primitives/hash/sponge_xof/shake/shake.c')) # SHAKE256 for Ed448
    sources.append(os.path.join(src_dir, 'utils/drbg/drbg.c')) # CTR_DRBG
    
    # Add wrapper if it exists
    wrapper = os.path.join(src_dir, 'utils', 'base_encryption.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)

    # Common includes
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
        os.path.join(src_dir, 'primitives/hash/sponge_xof/shake'), # For shake.h
        src_dir,
    ]
    
    # Macros
    macros = [
        ('AES___', '128'),
        ('FF_X', '1'),
        ('HAVE_ED448', '1'),
    ]

    return builder.build_target('core', sources, 
                                includes=includes,
                                macros=macros,
                                output_subdir='main')

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    log_dir = os.path.dirname(config.get_log_path('main', 'core'))
    os.makedirs(log_dir, exist_ok=True)
    
    with Logger(config.get_log_path('main', 'core')) as logger:
        build(Builder(config, logger))
