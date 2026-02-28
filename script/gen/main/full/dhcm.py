import os
from script.core import Builder

def build(builder: Builder):
    """Build DHCM dhcm.dll (Main)."""
    src_dir = builder.config.src_dir
    
    sources = builder.get_sources([
        os.path.join(src_dir, 'DHCM/core/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_fast/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_memory_hard/'),
        os.path.join(src_dir, 'DHCM/adapters/primitive_sponge_xof/'),
        os.path.join(src_dir, 'DHCM/adapters/legacy_alive/'),
        os.path.join(src_dir, 'DHCM/adapters/legacy_unsafe/'),
        os.path.join(src_dir, 'DHCM/utils/'),
    ], recursive=True)
    
    return builder.build_target('dhcm', sources, 
                                output_subdir='main/full',
                                macros=['DHCM_VERSION_MAJOR=1', 'DHCM_VERSION_MINOR=0',
                                        'DHCM_ENABLE_PRIMITIVE_FAST',
                                        'DHCM_ENABLE_PRIMITIVE_MEMORY_HARD',
                                        'DHCM_ENABLE_PRIMITIVE_SPONGE_XOF',
                                        'DHCM_ENABLE_LEGACY_ALIVE',
                                        'DHCM_ENABLE_LEGACY_UNSAFE'])

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('main', 'dhcm')) as logger:
        build(Builder(config, logger))
