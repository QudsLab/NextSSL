import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build hash_legacy.dll (Base Tier)."""
    src_dir = builder.config.src_dir
    
    # Combined sources from all legacy categories
    # Note: legacy_alive needs aes_core and md4 (which is in legacy_unsafe)
    sources = builder.get_sources([
        os.path.join(src_dir, 'legacy', 'alive'),
        os.path.join(src_dir, 'legacy', 'unsafe'),
        os.path.join(src_dir, 'primitives', 'cipher', 'aes_core')
    ], recursive=True)
    
    # Combined wrappers
    wrappers = [
        os.path.join(src_dir, 'utils', 'hash', 'legacy_alive.c'),
        os.path.join(src_dir, 'utils', 'hash', 'legacy_unsafe.c')
    ]
    
    for w in wrappers:
        if os.path.exists(w):
            sources.append(w)
        else:
            builder.logger.error(f"Wrapper not found: {w}")
            
    return builder.build_target('hash_legacy', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='base')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('base', 'hash_legacy')) as logger:
        builder = Builder(config, logger)
        build(builder)
