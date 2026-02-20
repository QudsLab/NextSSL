import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW server DLL for primitive fast algorithms."""
    src_dir = builder.config.src_dir
    
    # Core PoW logic + Server logic + Adapter implementation
    sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/server/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_fast/')
    ], recursive=True)
    
    # Add Base64 implementation
    sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    
    # Add Mock Dependencies (until Hash/DHCM DLLs are fully ready/exported)
    sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    
    # Wrapper
    wrapper = os.path.join(src_dir, 'utils/pow/server/primitive_fast.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    
    return builder.build_target(
        'primitive_fast',
        sources,
        extra_libs=[
            '-lpthread',
            # 'bin/partial/hash/primitive_fast.dll', # Mocked
            # 'bin/partial/dhcm/primitive_fast.dll'  # Mocked
        ],
        output_subdir='partial/pow/server',
        macros=['POW_ENABLE_SERVER', 'POW_ENABLE_PRIMITIVE_FAST']
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('partial/pow/server', 'primitive_fast')) as logger:
        build(Builder(config, logger))
