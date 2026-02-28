"""
Generator for hash.dll (Main Lite Tier)
Builds: SHA-256, SHA-512, BLAKE3 only
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build hash.dll with SHA-256, SHA-512, BLAKE3 only."""
    src_dir = builder.config.src_dir
    
    sources = []
    
    # SHA-256
    sha256_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast', 'sha256')
    ], recursive=True)
    sources.extend(sha256_sources)
    
    # SHA-512
    sha512_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast', 'sha512')
    ], recursive=True)
    sources.extend(sha512_sources)
    
    # BLAKE3
    blake3_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast', 'blake3')
    ], recursive=True)
    sources.extend(blake3_sources)
    
    # Lite hash wrappers (if they exist)
    wrapper_path = os.path.join(src_dir, 'interfaces', 'main', 'lite', 'hash.c')
    if os.path.exists(wrapper_path):
        sources.append(wrapper_path)
    
    return builder.build_target('hash', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='main/lite')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main_lite', 'hash')) as logger:
        builder = Builder(config, logger)
        success = build(builder)
        sys.exit(0 if success else 1)
