import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build primitive_memory_hard.dll."""
    src_dir = builder.config.src_dir
    
    # src/primitives/hash/memory_hard/
    sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard')
    ], recursive=True)
    
    wrapper = os.path.join(src_dir, 'utils', 'hash', 'primitive_memory_hard.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    else:
        builder.logger.error(f"Wrapper not found: {wrapper}")
    
    return builder.build_target('primitive_memory_hard', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='partial/hash')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('partial/hash', 'primitive_memory_hard')) as logger:
        builder = Builder(config, logger)
        build(builder)
