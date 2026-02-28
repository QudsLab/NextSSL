import os
from script.core import Builder

def build(builder: Builder):
    src_dir = builder.config.src_dir
    
    core_sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/')
    ], recursive=True)
    
    adapter_sources = []
    adapter_dirs = [
        os.path.join(src_dir, 'PoW/adapters/primitive_fast/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_memory_hard/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_sponge_xof/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_alive/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_unsafe/')
    ]
    
    for d in adapter_dirs:
        sources = builder.get_sources([d], recursive=True)
        adapter_sources.extend([s for s in sources if not s.endswith('dispatcher.c')])
    
    adapter_sources.append(os.path.join(src_dir, 'PoW/adapters/dispatcher_main.c'))

    hash_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash', 'fast'),
        os.path.join(src_dir, 'primitives', 'hash', 'sponge_xof'),
        os.path.join(src_dir, 'primitives', 'hash', 'memory_hard'),
        os.path.join(src_dir, 'legacy/alive/'),
        os.path.join(src_dir, 'legacy/unsafe/')
    ], recursive=True)
    
    hash_wrapper = os.path.join(src_dir, 'utils', 'hash', 'primitive_memory_hard.c')
    if os.path.exists(hash_wrapper):
        hash_sources.append(hash_wrapper)
    
    aes_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives/cipher/aes_core/')
    ], recursive=True)
    
    core_sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    core_sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    
    combined_sources = core_sources + adapter_sources + hash_sources + aes_sources + builder.get_sources([
        os.path.join(src_dir, 'PoW/server/'),
        os.path.join(src_dir, 'PoW/client/')
    ], recursive=True)
    
    wrapper = os.path.join(src_dir, 'utils/pow/combined/main.c')
    if os.path.exists(wrapper):
        combined_sources.append(wrapper)
    
    return builder.build_target(
        'pow_combined',
        combined_sources,
        extra_libs=['-lpthread'],
        output_subdir='main/full',
        macros=[
            'POW_ENABLE_SERVER', 
            'POW_ENABLE_CLIENT',
            'POW_ENABLE_PRIMITIVE_FAST',
            'POW_ENABLE_PRIMITIVE_MEMORY_HARD',
            'POW_ENABLE_PRIMITIVE_SPONGE_XOF',
            'POW_ENABLE_LEGACY_ALIVE',
            'POW_ENABLE_LEGACY_UNSAFE',
            'POW_NO_GENERIC_API'
        ]
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('main', 'pow_combined')) as logger:
        build(Builder(config, logger))
