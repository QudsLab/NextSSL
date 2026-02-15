import os
from script.core import Builder

def build(builder: Builder):
    """Build aes_aead.dll with GCM, CCM, OCB, EAX, SIV, GCM-SIV, AES-Poly1305."""
    src_dir = builder.config.src_dir
    
    # Collect AEAD sources
    # Note: AES core and CTR are required dependencies for most AEAD modes
    sources = builder.get_sources([
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ctr/'),
        os.path.join(src_dir, 'primitives/aead/aes_gcm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ccm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ocb/'),
        os.path.join(src_dir, 'primitives/aead/aes_eax/'),
        os.path.join(src_dir, 'primitives/aead/aes_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_gcm_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_poly1305/'),
        os.path.join(src_dir, 'primitives/mac/aes_cmac/'), # For SIV
    ], recursive=True)
    
    # Common includes
    includes = [
        os.path.join(src_dir, 'primitives/cipher/aes_core'),
        os.path.join(src_dir, 'primitives/cipher'),
        os.path.join(src_dir, 'primitives/mac'),
        src_dir,
    ]
    
    # Macros
    macros = [
        ('AES___', '128'),
    ]

    return builder.build_target('aes_aead', sources, 
                                includes=includes,
                                macros=macros,
                                output_subdir='partial/core')

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    log_dir = os.path.dirname(config.get_log_path('partial/core', 'aes_aead'))
    os.makedirs(log_dir, exist_ok=True)
    
    with Logger(config.get_log_path('partial/core', 'aes_aead')) as logger:
        build(Builder(config, logger))
