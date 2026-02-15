import os
from script.core import Builder

def build(builder: Builder):
    """Build core_cipher_main.dll (Base Tier) - Symmetric Encryption."""
    src_dir = builder.config.src_dir
    
    # Combined sources from all cipher categories
    sources = builder.get_sources([
        # aes_modes
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
        os.path.join(src_dir, 'legacy/alive/aes_ecb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cbc/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cfb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ofb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ctr/'),
        os.path.join(src_dir, 'primitives/cipher/aes_xts/'),
        os.path.join(src_dir, 'primitives/cipher/aes_kw/'),
        os.path.join(src_dir, 'primitives/cipher/aes_fpe/'),
        
        # aes_aead
        os.path.join(src_dir, 'primitives/aead/aes_gcm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ccm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ocb/'),
        os.path.join(src_dir, 'primitives/aead/aes_eax/'),
        os.path.join(src_dir, 'primitives/aead/aes_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_gcm_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_poly1305/'),
        os.path.join(src_dir, 'primitives/mac/aes_cmac/'),
        
        # stream_aead
        # os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/'), # Handled below
    ], recursive=True)
    
    # Explicitly list ChaCha20-Poly1305 sources to avoid picking up optional/monocypher-ed25519.c
    sources.append(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/chacha20_poly1305.c'))
    sources.append(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/monocypher.c'))
    
    # Add optional wrapper if it exists
    wrapper = os.path.join(src_dir, 'utils', 'base_encryption.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    
    # Common includes
    includes = [
        os.path.join(src_dir, 'primitives/cipher/aes_core'),
        os.path.join(src_dir, 'primitives/cipher'),
        os.path.join(src_dir, 'primitives/aead'),
        os.path.join(src_dir, 'primitives/mac'),
        os.path.join(src_dir, 'primitives/aead/chacha20_poly1305'),
        src_dir,
    ]
    
    # Macros
    macros = [
        ('AES___', '128'),
        ('FF_X', '1'),
    ]

    return builder.build_target('core_cipher_main', sources, 
                                includes=includes,
                                macros=macros,
                                output_subdir='base')

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    log_dir = os.path.dirname(config.get_log_path('base', 'core_cipher_main'))
    os.makedirs(log_dir, exist_ok=True)
    
    with Logger(config.get_log_path('base', 'core_cipher_main')) as logger:
        build(Builder(config, logger))
