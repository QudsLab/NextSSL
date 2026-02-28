"""
Generator for pqc_lite.dll (Main Lite Tier)
Builds: Unified PQC API (Kyber1024 + Dilithium5)
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build pqc_lite.dll with combined Kyber1024 and Dilithium5."""
    src_dir = builder.config.src_dir
    
    sources = []
    
    # ML-KEM-1024 and ML-DSA-87 with common dependencies
    pqc_sources = builder.get_sources([
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem', 'ml-kem-1024'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_sign', 'ml-dsa-87'),
        os.path.join(src_dir, 'PQCrypto', 'common')
    ], recursive=True)
    sources.extend(pqc_sources)
    
    # Ed25519 for hybrid schemes
    ed25519_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'ecc', 'ed25519')
    ], recursive=True)
    sources.extend(ed25519_sources)
    
    # Include keyexchange and signature wrappers since pqc.c calls them
    keyexchange_wrapper = os.path.join(src_dir, 'interfaces', 'main', 'lite', 'keyexchange.c')
    if os.path.exists(keyexchange_wrapper):
        sources.append(keyexchange_wrapper)
    
    signature_wrapper = os.path.join(src_dir, 'interfaces', 'main', 'lite', 'signature.c')
    if os.path.exists(signature_wrapper):
        sources.append(signature_wrapper)
    
    # Lite PQC wrappers
    wrapper_path = os.path.join(src_dir, 'interfaces', 'main', 'lite', 'pqc.c')
    if os.path.exists(wrapper_path):
        sources.append(wrapper_path)
    
    # PQC main wrapper (shared utility)
    pqc_main = os.path.join(src_dir, 'utils', 'pqc_main.c')
    if os.path.exists(pqc_main):
        sources.append(pqc_main)
    
    # Include directories for PQCrypto headers
    includes = [
        os.path.join(src_dir, 'PQCrypto', 'common'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_kem', 'ml-kem-1024', 'clean'),
        os.path.join(src_dir, 'PQCrypto', 'crypto_sign', 'ml-dsa-87', 'clean')
    ]
    
    return builder.build_target('pqc', sources,
                                extra_libs=['-lpthread'], 
                                includes=includes,
                                output_subdir='main/lite')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main_lite', 'pqc')) as logger:
        builder = Builder(config, logger)
        success = build(builder)
        sys.exit(0 if success else 1)
