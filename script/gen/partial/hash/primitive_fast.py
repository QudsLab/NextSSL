import os
import sys

# Ensure we can import from script.core
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build primitive_fast.dll."""
    src_dir = builder.config.src_dir
    
    # 1. Collect .c files from source directories (recursive)
    # src/primitives/hash/fast/
    sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast')
    ], recursive=True)
    
    # 2. Append Leyline wrapper file(s) from utils/hash/
    wrapper = os.path.join(src_dir, 'utils', 'hash', 'primitive_fast.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    else:
        builder.logger.error(f"Wrapper not found: {wrapper}")
    
    # 3. Build as shared library
    return builder.build_target('primitive_fast', sources, 
                                extra_libs=[], 
                                output_subdir='partial/hash')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('partial/hash', 'primitive_fast')) as logger:
        builder = Builder(config, logger)
        build(builder)
