import os
from script.core import Builder, Config, Logger

def build(builder: Builder):
    """Build sign_hash_based.dll with SPHINCS+."""
    src_dir = builder.config.src_dir
    
    # Collect algorithm sources
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
    
    sources = builder.get_sources(sphincs_dirs, recursive=True)
    
    # Add shared randomness layer (DRBG/UDBF)
    # Plus sha2.c required for SHA2-based SPHINCS+
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
    includes.extend(sphincs_dirs)

    return builder.build_target(
        'sign_hash_based', 
        sources, 
        output_subdir='partial/pqc',
        macros=['ENABLE_SPHINCS'],
        remove_macros=['EXCLUDE_SPHINCS'],
        includes=includes
    )

if __name__ == "__main__":
    # Allow standalone execution (for debugging)
    config = Config()
    with Logger(config.get_log_path('partial/pqc', 'sign_hash_based')) as logger:
        build(Builder(config, logger))
