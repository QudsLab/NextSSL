import os
from script.core import Builder

def build(builder: Builder):
    """Build PoW combined DLL for primitive sponge xof algorithms (SHA3)."""
    src_dir = builder.config.src_dir
    
    sources = builder.get_sources([
        os.path.join(src_dir, 'PoW/core/'),
        os.path.join(src_dir, 'PoW/server/'),
        os.path.join(src_dir, 'PoW/client/'),
        os.path.join(src_dir, 'PoW/adapters/primitive_sponge_xof/')
    ], recursive=True)
    
    # Add Base64 implementation
    sources.append(os.path.join(src_dir, 'utils/radix/base64.c'))
    
    # Add Mock Dependencies
    sources.append(os.path.join(src_dir, 'PoW/mock_deps.c'))
    
    # Wrapper
    wrapper = os.path.join(src_dir, 'utils/pow/combined/primitive_sponge_xof.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    
    return builder.build_target(
        'primitive_sponge_xof',
        sources,
        extra_libs=['-lpthread'],
        output_subdir='partial/pow/combined',
        macros=['POW_ENABLE_SERVER', 'POW_ENABLE_CLIENT', 'POW_ENABLE_PRIMITIVE_SPONGE_XOF']
    )

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    with Logger(config.get_log_path('partial/pow/combined', 'primitive_sponge_xof')) as logger:
        build(Builder(config, logger))
