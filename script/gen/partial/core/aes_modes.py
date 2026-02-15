import os
from script.core import Builder

def build(builder: Builder):
    """Build aes_modes.dll with ECB, CBC, CFB, OFB, CTR, XTS, KW, FPE."""
    src_dir = builder.config.src_dir
    
    # Collect cipher mode sources
    sources = builder.get_sources([
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
        os.path.join(src_dir, 'legacy/alive/aes_ecb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cbc/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cfb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ofb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ctr/'),
        os.path.join(src_dir, 'primitives/cipher/aes_xts/'),
        os.path.join(src_dir, 'primitives/cipher/aes_kw/'),
        os.path.join(src_dir, 'primitives/cipher/aes_fpe/'),
    ], recursive=True)
    
    # Common includes
    includes = [
        os.path.join(src_dir, 'primitives/cipher/aes_core'),
        os.path.join(src_dir, 'primitives/cipher'),
        src_dir,
    ]
    
    # Macros
    macros = [
        ('AES___', '128'),
        ('FF_X', '1'),
    ]

    return builder.build_target('aes_modes', sources, 
                                includes=includes,
                                macros=macros,
                                output_subdir='partial/core')

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    # Ensure directory exists
    log_dir = os.path.dirname(config.get_log_path('partial/core', 'aes_modes'))
    os.makedirs(log_dir, exist_ok=True)
    
    with Logger(config.get_log_path('partial/core', 'aes_modes')) as logger:
        build(Builder(config, logger))
