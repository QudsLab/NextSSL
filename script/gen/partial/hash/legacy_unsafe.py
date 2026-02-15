import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

from script.core import Config, Logger, Builder

def build(builder: Builder):
    """Build legacy_unsafe.dll."""
    src_dir = builder.config.src_dir
    
    # src/legacy/unsafe/ (recursive)
    sources = builder.get_sources([
        os.path.join(src_dir, 'legacy', 'unsafe')
    ], recursive=True)
    
    wrapper = os.path.join(src_dir, 'utils', 'hash', 'legacy_unsafe.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    else:
        builder.logger.error(f"Wrapper not found: {wrapper}")
    
    return builder.build_target('legacy_unsafe', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='partial/hash')

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('partial/hash', 'legacy_unsafe')) as logger:
        builder = Builder(config, logger)
        build(builder)
