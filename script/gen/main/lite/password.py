"""
Generator for password_lite.dll (Main Lite Tier)
Builds: HKDF, Argon2id only
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build password_lite.dll with HKDF and Argon2id only."""
    src_dir = builder.config.src_dir
    
    sources = []
    
    # HKDF (SHA256-based KDF from PQCrypto/common)
    hkdf_dir = os.path.join(src_dir, 'PQCrypto', 'common', 'hkdf')
    sha2_file = os.path.join(src_dir, 'PQCrypto', 'common', 'sha2.c')
    fips202_file = os.path.join(src_dir, 'PQCrypto', 'common', 'fips202.c')
    
    if os.path.exists(hkdf_dir):
        for file in os.listdir(hkdf_dir):
            if file.endswith('.c'):
                sources.append(os.path.join(hkdf_dir, file))
    
    if os.path.exists(sha2_file):
        sources.append(sha2_file)
    
    if os.path.exists(fips202_file):
        sources.append(fips202_file)
    
    # Argon2id (with utils and blake2)
    argon2_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard', 'Argon2id'),
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard', 'utils'),
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard', 'blake2')
    ], recursive=True)
    sources.extend(argon2_sources)
    
    # Lite password wrappers
    wrapper_path = os.path.join(src_dir, 'interfaces', 'main', 'lite', 'password.c')
    if os.path.exists(wrapper_path):
        sources.append(wrapper_path)
    
    return builder.build_target('password', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='main/lite')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main_lite', 'password')) as logger:
        builder = Builder(config, logger)
        success = build(builder)
        sys.exit(0 if success else 1)
