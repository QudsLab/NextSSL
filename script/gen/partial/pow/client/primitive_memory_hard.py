import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW client DLL for primitive memory hard algorithms."""
    src_dir = builder.config.src_dir
    
    sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/client/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_memory_hard/')
    ], recursive=True)
    
    # Add Base64 implementation
    sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    
    # Add Mock Dependencies
    sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))

    # Add Real Hash Primitive Sources (Argon2)
    sources.extend(builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard')
    ], recursive=True))
    
    hash_wrapper = os.path.join(src_dir, 'utils', 'hash', 'primitive_memory_hard.c')
    if os.path.exists(hash_wrapper):
        sources.append(hash_wrapper)
    
    # Wrapper
    wrapper = os.path.join(src_dir, 'utils/pow/client/primitive_memory_hard.c')
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
        output_subdir='partial/pow/client',
        macros=['POW_ENABLE_CLIENT', 'POW_ENABLE_PRIMITIVE_MEMORY_HARD']
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('partial/pow/client', 'primitive_memory_hard')) as logger:
        build(Builder(config, logger))
