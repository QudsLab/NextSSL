import os
from script.core import Builder, Config, Logger

def build(builder: Builder):
    """Build sign_lattice.dll with ML-DSA and Falcon."""
    src_dir = builder.config.src_dir
    
    # Collect algorithm sources
    # ML-DSA
    mldsa_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-44/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-65/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-87/clean/'),
    ]
    
    # Falcon
    falcon_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-1024/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-padded-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-padded-1024/clean/'),
    ]
    
    sources = builder.get_sources(mldsa_dirs + falcon_dirs, recursive=True)
    
    # Add shared randomness layer (DRBG/UDBF)
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
    includes.extend(mldsa_dirs)
    includes.extend(falcon_dirs)

    return builder.build_target(
        'sign_lattice', 
        sources, 
        output_subdir='partial/pqc',
        macros=['ENABLE_ML_DSA', 'ENABLE_FALCON'],
        includes=includes
    )

if __name__ == "__main__":
    # Allow standalone execution (for debugging)
    config = Config()
    with Logger(config.get_log_path('partial/pqc', 'sign_lattice')) as logger:
        build(Builder(config, logger))
