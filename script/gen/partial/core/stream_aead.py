import os
from script.core import Builder

def build(builder: Builder):
    """Build stream_aead.dll with ChaCha20-Poly1305 (Monocypher backend)."""
    src_dir = builder.config.src_dir
    
    # Collect Stream AEAD sources
    # Explicitly list sources to avoid picking up optional/monocypher-ed25519.c which requires EdDSA
    sources = [
        os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/chacha20_poly1305.c'),
        os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/monocypher.c'),
    ]
    
    # Common includes
    includes = [
        os.path.join(src_dir, 'primitives/aead/chacha20_poly1305'),
        src_dir,
    ]
    
    return builder.build_target('stream_aead', sources, 
                                includes=includes,
                                output_subdir='partial/core')

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    log_dir = os.path.dirname(config.get_log_path('partial/core', 'stream_aead'))
    os.makedirs(log_dir, exist_ok=True)
    
    with Logger(config.get_log_path('partial/core', 'stream_aead')) as logger:
        build(Builder(config, logger))
