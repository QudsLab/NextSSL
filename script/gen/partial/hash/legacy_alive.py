import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build legacy_alive.dll."""
    src_dir = builder.config.src_dir
    
    # Sources:
    # 1. src/legacy/alive/ (recursive)
    # 2. src/primitives/cipher/aes_core/ (for AES-ECB)
    # 3. src/legacy/unsafe/md4/ (for NT Hash)
    sources = builder.get_sources([
        os.path.join(src_dir, 'legacy', 'alive'),
        os.path.join(src_dir, 'primitives', 'cipher', 'aes_core'),
        os.path.join(src_dir, 'legacy', 'unsafe', 'md4')
    ], recursive=True)
    
    wrapper = os.path.join(src_dir, 'utils', 'hash', 'legacy_alive.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    else:
        builder.logger.error(f"Wrapper not found: {wrapper}")
    
    return builder.build_target('legacy_alive', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='partial/hash')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('partial/hash', 'legacy_alive')) as logger:
        builder = Builder(config, logger)
        build(builder)
