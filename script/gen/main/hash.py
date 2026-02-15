import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build hash.dll (Main Tier)."""
    src_dir = builder.config.src_dir
    
    # Combined sources from everything
    sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash'),
        os.path.join(src_dir, 'legacy'),
        os.path.join(src_dir, 'primitives', 'cipher', 'aes_core')
    ], recursive=True)
    
    # All wrappers in utils/hash
    wrappers = builder.get_sources([
        os.path.join(src_dir, 'utils', 'hash')
    ], recursive=False) # Non-recursive to just get the wrappers
    
    sources.extend(wrappers)
            
    return builder.build_target('hash', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='main')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main', 'hash')) as logger:
        builder = Builder(config, logger)
        build(builder)
