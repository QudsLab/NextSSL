"""
Generator for pow_lite.dll (Main Lite Tier)
Builds: SHA-256 based PoW only
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build pow_lite.dll with SHA-256 based PoW only."""
    src_dir = builder.config.src_dir
    
    sources = []
    
    # SHA-256 (for PoW hashing)
    sha256_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast', 'sha256')
    ], recursive=True)
    sources.extend(sha256_sources)
    
    # Lite PoW wrappers (standalone, doesn't use complex PoW utils)
    wrapper_path = os.path.join(src_dir, 'interfaces', 'main', 'lite', 'pow.c')
    if os.path.exists(wrapper_path):
        sources.append(wrapper_path)
    
    return builder.build_target('pow', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='main/lite')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main_lite', 'pow')) as logger:
        builder = Builder(config, logger)
        success = build(builder)
        sys.exit(0 if success else 1)
