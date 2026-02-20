import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW server DLL for primitive memory hard algorithms."""
    src_dir = builder.config.src_dir
    
    sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/server/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_memory_hard/')
    ], recursive=True)
    
    # Add Base64 implementation
    sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    
    # Add Mock Dependencies
    sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    
    # Wrapper
    wrapper = os.path.join(src_dir, 'utils/pow/server/primitive_memory_hard.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    
    return builder.build_target(
        'primitive_memory_hard',
        sources,
        extra_libs=[
            '-lpthread',
            # 'bin/partial/hash/primitive_memory_hard.dll',
            # 'bin/partial/dhcm/primitive_memory_hard.dll'
        ],
        output_subdir='partial/pow/server',
        macros=['POW_ENABLE_SERVER', 'POW_ENABLE_PRIMITIVE_MEMORY_HARD']
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('partial/pow/server', 'primitive_memory_hard')) as logger:
        build(Builder(config, logger))
