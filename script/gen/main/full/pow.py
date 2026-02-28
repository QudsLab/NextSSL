import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW Main DLLs (Server & Client - All Algorithms)."""
    src_dir = builder.config.src_dir
    
    # --- Shared Sources ---
    core_sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/')
    ], recursive=True)
    
    # Adapters (All)
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
    
    # Unified Main Dispatcher
    adapter_sources.append(os.path.join(src_dir, 'PoW/adapters/dispatcher_main.c'))

    # Hash Implementations (required for linking)
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
    
    # AES Core (required for AES-ECB in legacy_alive)
    aes_sources = builder.get_sources([
        os.path.join(src_dir, 'primitives/cipher/aes_core/')
    ], recursive=True)
    
    core_sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    core_sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    
    # --- Server Build ---
    server_sources = core_sources + adapter_sources + hash_sources + aes_sources + builder.get_sources([
        os.path.join(src_dir, 'PoW/server/')
    ], recursive=True)
    
    # Generic API
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/api.c'))
    
    # Include ALL wrappers (guarded by POW_NO_GENERIC_API)
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/primitive_fast.c'))
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/primitive_memory_hard.c'))
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/primitive_sponge_xof.c'))
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/legacy_alive.c'))
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/legacy_unsafe.c'))
    
    ret_server = builder.build_target(
        'pow_server',
        server_sources,
        extra_libs=['-lpthread'],
        output_subdir='main/full',
        macros=[
            'POW_ENABLE_SERVER', 
            'POW_ENABLE_PRIMITIVE_FAST',
            'POW_ENABLE_PRIMITIVE_MEMORY_HARD',
            'POW_ENABLE_PRIMITIVE_SPONGE_XOF',
            'POW_ENABLE_LEGACY_ALIVE',
            'POW_ENABLE_LEGACY_UNSAFE',
            'POW_NO_GENERIC_API'
        ]
    )
    
    # --- Client Build ---
    client_sources = core_sources + adapter_sources + hash_sources + aes_sources + builder.get_sources([
        os.path.join(src_dir, 'PoW/client/')
    ], recursive=True)
    
    # Generic API
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/api.c'))
    
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/primitive_fast.c'))
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/primitive_memory_hard.c'))
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/primitive_sponge_xof.c'))
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/legacy_alive.c'))
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/legacy_unsafe.c'))
    
    ret_client = builder.build_target(
        'pow_client',
        client_sources,
        extra_libs=['-lpthread'],
        output_subdir='main/full',
        macros=[
            'POW_ENABLE_CLIENT', 
            'POW_ENABLE_PRIMITIVE_FAST',
            'POW_ENABLE_PRIMITIVE_MEMORY_HARD',
            'POW_ENABLE_PRIMITIVE_SPONGE_XOF',
            'POW_ENABLE_LEGACY_ALIVE',
            'POW_ENABLE_LEGACY_UNSAFE',
            'POW_NO_GENERIC_API'
        ]
    )
    
    return ret_server or ret_client

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('main', 'pow')) as logger:
        build(Builder(config, logger))
