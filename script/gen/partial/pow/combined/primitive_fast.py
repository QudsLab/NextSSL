import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW combined DLL (server+client) for primitive fast algorithms."""
    src_dir = builder.config.src_dir
    
    # Core PoW logic + Server + Client + Adapter implementation
    sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/server/'),
        os.path.join(src_dir, 'PoW/client/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_fast/')
    ], recursive=True)

    # Add Base64 implementation
    sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    
    # Add Hash Primitive Sources (Fast)
    sources.extend(builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast')
    ], recursive=True))
    
    # Add Mock Dependencies
    sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    
    # Wrapper
    wrapper = os.path.join(src_dir, 'utils/pow/combined/primitive_fast.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    
    return builder.build_target(
        'primitive_fast',
        sources,
        extra_libs=[
            '-lpthread',
            # 'bin/partial/hash/primitive_fast.dll',
            # 'bin/partial/dhcm/primitive_fast.dll'
        ],
        output_subdir='partial/pow/combined',
        macros=['POW_ENABLE_SERVER', 'POW_ENABLE_CLIENT', 'POW_ENABLE_PRIMITIVE_FAST']
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('partial/pow/combined', 'primitive_fast')) as logger:
        build(Builder(config, logger))
