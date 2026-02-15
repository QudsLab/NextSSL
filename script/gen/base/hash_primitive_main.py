import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build hash_primitive.dll (Base Tier)."""
    src_dir = builder.config.src_dir
    
    # Combined sources from all primitive categories
    sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast'),
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard'),
        os.path.join(src_dir, 'primitives', 'hash', 'sponge_xof')
    ], recursive=True)
    
    # Combined wrappers
    wrappers = [
        os.path.join(src_dir, 'utils', 'hash', 'primitive_fast.c'),
        os.path.join(src_dir, 'utils', 'hash', 'primitive_memory_hard.c'),
        os.path.join(src_dir, 'utils', 'hash', 'primitive_sponge_xof.c')
    ]
    
    for w in wrappers:
        if os.path.exists(w):
            sources.append(w)
        else:
            builder.logger.error(f"Wrapper not found: {w}")
            
    return builder.build_target('hash_primitive', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='base')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('base', 'hash_primitive')) as logger:
        builder = Builder(config, logger)
        build(builder)
