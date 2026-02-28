"""
Generator for signature_lite.dll (Main Lite Tier)
Builds: Ed25519, Dilithium5 only
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build signature_lite.dll with Ed25519 and Dilithium5 only."""
    src_dir = builder.config.src_dir
    
    sources = []
    
    # Ed25519
    ed25519_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'ecc', 'ed25519')
    ], recursive=True)
    sources.extend(ed25519_sources)
    
    # ML-DSA-87 (Dilithium5 renamed) with common dependencies
    dilithium_sources = builder.get_sources([
        os.path.join(src_dir, 'PQCrypto', 'crypto_sign', 'ml-dsa-87'),
        os.path.join(src_dir, 'PQCrypto', 'common')
    ], recursive=True)
    sources.extend(dilithium_sources)
    
    # Lite signature wrappers
    wrapper_path = os.path.join(src_dir, 'interfaces', 'main', 'lite', 'signature.c')
    if os.path.exists(wrapper_path):
        sources.append(wrapper_path)
    
    # PQC main wrapper (shared utility)
    pqc_main = os.path.join(src_dir, 'utils', 'pqc_main.c')
    if os.path.exists(pqc_main):
        sources.append(pqc_main)
    
    # Include directories for PQCrypto headers
    includes = [
        os.path.join(src_dir, 'PQCrypto', 'common'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_sign', 'ml-dsa-87', 'clean')
    ]
    
    return builder.build_target('signature', sources, 
                                extra_libs=['-lpthread'], 
                                includes=includes,
                                output_subdir='main/lite')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main_lite', 'signature')) as logger:
        builder = Builder(config, logger)
        success = build(builder)
        sys.exit(0 if success else 1)
