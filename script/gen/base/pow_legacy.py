import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW Legacy DLLs (Server & Client)."""
    src_dir = builder.config.src_dir
    
    # --- Shared Sources ---
    core_sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/')
    ], recursive=True)
    
    # Adapters (Legacy)
    # Exclude individual dispatchers
    adapter_sources = []
    adapter_dirs = [
        os.path.join(src_dir, 'PoW/adapters/legacy_alive/'),
        os.path.join(src_dir, 'PoW/adapters/legacy_unsafe/')
    ]
    
    for d in adapter_dirs:
        sources = builder.get_sources([d], recursive=True)
        adapter_sources.extend([s for s in sources if not s.endswith('dispatcher.c')])
        
    # Include unified legacy dispatcher
    adapter_sources.append(os.path.join(src_dir, 'PoW/adapters/dispatcher_legacy.c'))

    # Legacy Hash Implementations (required for linking)
    hash_sources = builder.get_sources([
        os.path.join(src_dir, 'legacy/alive/'),
        os.path.join(src_dir, 'legacy/unsafe/')
    ], recursive=True)
    
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
    
    # Specific wrappers (guarded by POW_NO_GENERIC_API)
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/legacy_alive.c'))
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/legacy_unsafe.c'))
    
    ret_server = builder.build_target(
        'pow_server_legacy',
        server_sources,
        extra_libs=['-lpthread'],
        output_subdir='base',
        macros=[
            'POW_ENABLE_SERVER', 
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
    
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/legacy_alive.c'))
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/legacy_unsafe.c'))
    
    ret_client = builder.build_target(
        'pow_client_legacy',
        client_sources,
        extra_libs=['-lpthread'],
        output_subdir='base',
        macros=[
            'POW_ENABLE_CLIENT', 
            'POW_ENABLE_LEGACY_ALIVE',
            'POW_ENABLE_LEGACY_UNSAFE',
            'POW_NO_GENERIC_API'
        ]
    )
    
    return ret_server or ret_client

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('base', 'pow_legacy')) as logger:
        build(Builder(config, logger))
