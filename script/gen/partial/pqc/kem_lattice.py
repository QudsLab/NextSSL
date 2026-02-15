import os
from script.core import Builder, Config, Logger

def build(builder: Builder):
    """Build kem_lattice.dll with ML-KEM-512/768/1024."""
    src_dir = builder.config.src_dir
    
    # Collect algorithm sources
    sources = builder.get_sources([
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-768/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-1024/clean/'),
    ], recursive=True)
    
    # Add shared randomness layer (DRBG/UDBF)
    sources.extend(builder.get_sources([
        os.path.join(src_dir, 'PQCrypto/common'),
        os.path.join(src_dir, 'PQCrypto/common/drbg'),
        os.path.join(src_dir, 'PQCrypto/common/hkdf'),
    ], recursive=False)) # Non-recursive to avoid picking up other things if any
    
    # Specifically add fips202.c if it's not in common root or needs specific handling?
    # common/ has randombytes.c, fips202.c, sha2.c, etc.
    # checking file list: 
    # src/PQCrypto/common/randombytes.c
    # src/PQCrypto/common/drbg/drbg.c
    # src/PQCrypto/common/hkdf/hkdf.c
    # src/PQCrypto/common/fips202.c
    
    # The above get_sources call for 'common' non-recursive will get randombytes.c, fips202.c, sha2.c etc.
    # verifying if recursive=False works as expected (only files in dir).
    # Builder.get_sources implementation:
    # if recursive: os.walk...
    # else: os.listdir(d)... if file.endswith('.c')...
    # So yes, recursive=False gets files in 'common'.
    
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
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem', 'ml-kem-512', 'clean'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem', 'ml-kem-768', 'clean'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem', 'ml-kem-1024', 'clean'),
    ]

    return builder.build_target(
        'kem_lattice', 
        sources, 
        output_subdir='partial/pqc',
        macros=['ENABLE_ML_KEM'],
        includes=includes
    )

if __name__ == "__main__":
    # Allow standalone execution (for debugging)
    config = Config()
    with Logger(config.get_log_path('partial/pqc', 'kem_lattice')) as logger:
        build(Builder(config, logger))
