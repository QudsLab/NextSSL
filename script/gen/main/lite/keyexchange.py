"""
Generator for keyexchange_lite.dll (Main Lite Tier)
Builds: X25519, Kyber1024 only
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build keyexchange_lite.dll with X25519 and Kyber1024 only."""
    src_dir = builder.config.src_dir
    
    sources = []
    
    # X25519 (Curve25519 - use ed25519 implementation)
    x25519_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'ecc', 'ed25519')
    ], recursive=True)
    sources.extend(x25519_sources)
    
    # ML-KEM-1024 (Kyber1024 renamed) with common dependencies
    kyber_sources = builder.get_sources([
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem', 'ml-kem-1024'),
        os.path.join(src_dir, 'PQCrypto', 'common')
    ], recursive=True)
    sources.extend(kyber_sources)
    
    # Lite keyexchange wrappers
    wrapper_path = os.path.join(src_dir, 'interfaces', 'main', 'lite', 'keyexchange.c')
    if os.path.exists(wrapper_path):
        sources.append(wrapper_path)
    
    # PQC main wrapper (shared utility)
    pqc_main = os.path.join(src_dir, 'utils', 'pqc_main.c')
    if os.path.exists(pqc_main):
        sources.append(pqc_main)
    
    # Include directories for PQCrypto headers
    includes = [
        os.path.join(src_dir, 'PQCrypto', 'common'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem', 'ml-kem-1024', 'clean')
    ]
    
    return builder.build_target('keyexchange', sources,
                                extra_libs=['-lpthread'], 
                                includes=includes,
                                output_subdir='main/lite')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main_lite', 'keyexchange')) as logger:
        builder = Builder(config, logger)
        success = build(builder)
        sys.exit(0 if success else 1)
