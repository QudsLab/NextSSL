import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW combined DLL for legacy alive algorithms."""
    src_dir = builder.config.src_dir
    
    source_dirs = [
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/client/'),
        os.path.join(src_dir, 'PoW/server/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_alive/'),
        os.path.join(src_dir, 'legacy/alive/md5/'),
        os.path.join(src_dir, 'legacy/alive/sha1/'),
        os.path.join(src_dir, 'legacy/alive/ripemd160/'),
        os.path.join(src_dir, 'legacy/alive/whirlpool/'),
        os.path.join(src_dir, 'legacy/alive/nt_hash/'),
        os.path.join(src_dir, 'legacy/unsafe/md4/')
    ]
    combined_dir = os.path.join(src_dir, 'PoW/combined/')
    if os.path.exists(combined_dir):
        source_dirs.append(combined_dir)
    sources = builder.get_sources(source_dirs, recursive=True)
    sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    wrapper = os.path.join(src_dir, 'utils/pow/combined/legacy_alive.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    
    return builder.build_target(
        'legacy_alive',
        sources,
        extra_libs=['-lpthread'],
        output_subdir='partial/pow/combined',
        macros=['POW_ENABLE_SERVER', 'POW_ENABLE_CLIENT', 'POW_ENABLE_LEGACY_ALIVE']
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('partial/pow/combined', 'legacy_alive')) as logger:
        build(Builder(config, logger))
