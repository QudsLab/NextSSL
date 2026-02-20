import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW Primitive DLLs (Server & Client)."""
    src_dir = builder.config.src_dir
    
    # --- Shared Sources ---
    # Core PoW logic
    core_sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/')
    ], recursive=True)
    
    # Adapters (Primitive)
    # Exclude individual dispatchers to avoid multiple definitions
    adapter_sources = []
    adapter_dirs = [
        os.path.join(src_dir, 'PoW/adapters/primitive_fast/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_memory_hard/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_sponge_xof/')
    ]
    
    for d in adapter_dirs:
        sources = builder.get_sources([d], recursive=True)
        adapter_sources.extend([s for s in sources if not s.endswith('dispatcher.c')])
    
    # Include the unified dispatcher for primitive base
    adapter_sources.append(os.path.join(src_dir, 'PoW/adapters/dispatcher_primitive.c'))
    
    # Base64
    core_sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    
    # Mock Deps (until integrated)
    core_sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    
    # --- Server Build ---
    server_sources = core_sources + adapter_sources + builder.get_sources([
        os.path.join(src_dir, 'PoW/server/')
    ], recursive=True)
    
    # Wrappers (Generic + Specific)
    # Include the generic API implementation
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/api.c'))
    
    # Include specific wrappers (compiled with POW_NO_GENERIC_API via target macro)
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/primitive_fast.c'))
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/primitive_memory_hard.c'))
    server_sources.append(os.path.join(src_dir, 'utils/pow/server/primitive_sponge_xof.c'))
    
    ret_server = builder.build_target(
        'pow_server_primitive',
        server_sources,
        extra_libs=['-lpthread'],
        output_subdir='base',
        macros=[
            'POW_ENABLE_SERVER', 
            'POW_ENABLE_PRIMITIVE_FAST',
            'POW_ENABLE_PRIMITIVE_MEMORY_HARD',
            'POW_ENABLE_PRIMITIVE_SPONGE_XOF',
            'POW_NO_GENERIC_API'  # Disable generic API in specific wrappers
        ]
    )
    
    # --- Client Build ---
    client_sources = core_sources + adapter_sources + builder.get_sources([
        os.path.join(src_dir, 'PoW/client/')
    ], recursive=True)
    
    # Include the generic API implementation
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/api.c'))
    
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/primitive_fast.c'))
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/primitive_memory_hard.c'))
    client_sources.append(os.path.join(src_dir, 'utils/pow/client/primitive_sponge_xof.c'))
    
    ret_client = builder.build_target(
        'pow_client_primitive',
        client_sources,
        extra_libs=['-lpthread'],
        output_subdir='base',
        macros=[
            'POW_ENABLE_CLIENT', 
            'POW_ENABLE_PRIMITIVE_FAST',
            'POW_ENABLE_PRIMITIVE_MEMORY_HARD',
            'POW_ENABLE_PRIMITIVE_SPONGE_XOF',
            'POW_NO_GENERIC_API'  # Disable generic API in specific wrappers
        ]
    )
    
    return ret_server or ret_client

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('base', 'pow_primitive')) as logger:
        build(Builder(config, logger))
