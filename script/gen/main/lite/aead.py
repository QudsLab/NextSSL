"""
Generator for aead_lite.dll (Main Lite Tier)
Builds: AES-256-GCM, ChaCha20-Poly1305 only
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build aead_lite.dll with AES-256-GCM and ChaCha20-Poly1305 only."""
    src_dir = builder.config.src_dir
    
    sources = []
    
    # AES-256-GCM (requires AES core + CTR mode)
    aes_gcm_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'cipher', 'aes_core'),
        os.path.join(src_dir, 'primitives', 'cipher', 'aes_ctr'),
        os.path.join(src_dir, 'primitives', 'aead', 'aes_gcm')
    ], recursive=True)
    sources.extend(aes_gcm_sources)
    
    # ChaCha20-Poly1305 (includes monocypher with ChaCha20)
    chacha_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'aead', 'chacha20_poly1305')
    ], recursive=True)
    sources.extend(chacha_sources)
    
    # Lite AEAD wrappers
    wrapper_path = os.path.join(src_dir, 'interfaces', 'main', 'lite', 'aead.c')
    if os.path.exists(wrapper_path):
        sources.append(wrapper_path)
    
    # Base encryption wrapper (shared utility)
    base_enc = os.path.join(src_dir, 'utils', 'base_encryption.c')
    if os.path.exists(base_enc):
        sources.append(base_enc)
    
    return builder.build_target('aead', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='main/lite')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main_lite', 'aead')) as logger:
        builder = Builder(config, logger)
        success = build(builder)
        sys.exit(0 if success else 1)
