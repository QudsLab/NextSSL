import os
from script.core import Builder, Config, Logger

def build(builder: Builder):
    """Build pqc_kem_main.dll with ALL KEM algorithms."""
    src_dir = builder.config.src_dir
    
    # KEM Lattice (ML-KEM)
    kem_lattice_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-768/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-1024/clean/'),
    ]
    
    # KEM Code-based (HQC + McEliece)
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
    
    sources = builder.get_sources(kem_lattice_dirs + hqc_dirs + mceliece_dirs, recursive=True)
    
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
    includes.extend(kem_lattice_dirs)
    includes.extend(hqc_dirs)
    includes.extend(mceliece_dirs)

    return builder.build_target(
        'pqc_kem_main', 
        sources, 
        output_subdir='base',
        macros=['ENABLE_ML_KEM', 'ENABLE_HQC', 'ENABLE_MCELIECE'],
        includes=includes
    )

if __name__ == "__main__":
    # Allow standalone execution (for debugging)
    config = Config()
    with Logger(config.get_log_path('base', 'pqc_kem_main')) as logger:
        build(Builder(config, logger))
