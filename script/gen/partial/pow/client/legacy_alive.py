import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW client DLL for legacy alive algorithms."""
    src_dir = builder.config.src_dir
    
    sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/client/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_alive/'),
        os.path.join(src_dir, 'legacy/alive/md5/'),
        os.path.join(src_dir, 'legacy/alive/sha1/'),
        os.path.join(src_dir, 'legacy/alive/ripemd160/'),
        os.path.join(src_dir, 'legacy/alive/whirlpool/'),
        os.path.join(src_dir, 'legacy/alive/nt_hash/'),
        os.path.join(src_dir, 'legacy/unsafe/md4/')  # Needed for NT hash
    ], recursive=True)
    
    # Add Base64 implementation
    sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    
    # Add Mock Dependencies
    sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    
    # Wrapper
    wrapper = os.path.join(src_dir, 'utils/pow/client/legacy_alive.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    
    return builder.build_target(
        'legacy_alive',
        sources,
        extra_libs=['-lpthread'],
        output_subdir='partial/pow/client',
        macros=['POW_ENABLE_CLIENT', 'POW_ENABLE_LEGACY_ALIVE']
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('partial/pow/client', 'legacy_alive')) as logger:
        build(Builder(config, logger))
