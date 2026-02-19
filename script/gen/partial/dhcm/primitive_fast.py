import os
from script.core import Builder

def build(builder: Builder):
    """Build DHCM primitive_fast.dll."""
    src_dir = builder.config.src_dir
    
    sources = builder.get_sources([
        os.path.join(src_dir, 'DHCM/core/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_fast/'),
        os.path.join(src_dir, 'DHCM/utils/'),
    ], recursive=True)
    
    return builder.build_target('primitive_fast', sources, 
                                output_subdir='partial/dhcm',
                                macros=['DHCM_VERSION_MAJOR=1', 'DHCM_VERSION_MINOR=0', 'DHCM_ENABLE_PRIMITIVE_FAST'])

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('partial/dhcm', 'primitive_fast')) as logger:
        build(Builder(config, logger))
