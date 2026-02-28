import os
from script.core import Builder, Config, Logger

def build(builder: Builder):
    """Build pqc.dll with ALL PQC algorithms."""
    src_dir = builder.config.src_dir
    
    # ── KEM ──
    kem_lattice_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-768/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-1024/clean/'),
    ]
    hqc_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_kem/hqc-128/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/hqc-192/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/hqc-256/clean/'),
    ]
    mceliece_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece348864/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece348864f/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece460896/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece460896f/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece6688128/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece6688128f/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece6960119/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece6960119f/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece8192128/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece8192128f/clean/'),
    ]
    
    # ── SIGN ──
    mldsa_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-44/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-65/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-87/clean/'),
    ]
    falcon_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-1024/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-padded-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-padded-1024/clean/'),
    ]
    sphincs_dirs = [
        # SHA2 variants
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-128f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-128s-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-192f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-192s-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-256f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-256s-simple/clean/'),
        # SHAKE variants
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-128f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-128s-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-192f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-192s-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-256f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-256s-simple/clean/'),
    ]
    
    all_dirs = kem_lattice_dirs + hqc_dirs + mceliece_dirs + mldsa_dirs + falcon_dirs + sphincs_dirs
    sources = builder.get_sources(all_dirs, recursive=True)
    
    # Add shared randomness layer
    common_files = builder.get_sources([
        os.path.join(src_dir, 'PQCrypto/common'),
        os.path.join(src_dir, 'PQCrypto/common/drbg'),
        os.path.join(src_dir, 'PQCrypto/common/hkdf'),
    ], recursive=False)
    sources.extend(common_files)
    
    # Add wrapper
    wrapper = os.path.join(src_dir, 'utils/pqc_main.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    else:
        builder.logger.error(f"Wrapper not found: {wrapper}")
        return False
    
    # Additional includes for PQC
    includes = [
        os.path.join(src_dir, 'PQCrypto'),
        os.path.join(src_dir, 'PQCrypto', 'common'),
    ]
    includes.extend(all_dirs)

    return builder.build_target(
        'pqc', 
        sources, 
        output_subdir='main',
        macros=[
            'ENABLE_ML_KEM', 'ENABLE_HQC', 'ENABLE_MCELIECE',
            'ENABLE_ML_DSA', 'ENABLE_FALCON', 'ENABLE_SPHINCS'
        ],
        remove_macros=['EXCLUDE_SPHINCS'],
        includes=includes
    )

if __name__ == "__main__":
    # Allow standalone execution (for debugging)
    config = Config()
    with Logger(config.get_log_path('main', 'pqc')) as logger:
        build(Builder(config, logger))
