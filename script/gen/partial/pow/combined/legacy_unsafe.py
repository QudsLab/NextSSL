import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW combined DLL for legacy unsafe algorithms."""
    src_dir = builder.config.src_dir
    
    sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/client/'),
        os.path.join(src_dir, 'PoW/server/'),
        os.path.join(src_dir, 'PoW/combined/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_unsafe/'),
        os.path.join(src_dir, 'legacy/unsafe/')
    ], recursive=True) 
    # Add Base64 implementation
    sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    
    # Add Mock Dependencies
    sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    
    # Wrapper
    wrapper = os.path.join(src_dir, 'utils/pow/combined/legacy_unsafe.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    
    return builder.build_target(
        'legacy_unsafe',
        sources,
        extra_libs=['-lpthread'],
        output_subdir='partial/pow/combined',
        macros=['POW_ENABLE_SERVER', 'POW_ENABLE_CLIENT', 'POW_ENABLE_LEGACY_UNSAFE']
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('partial/pow/combined', 'legacy_unsafe')) as logger:
        build(Builder(config, logger))
