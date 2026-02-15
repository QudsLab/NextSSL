import os
from script.core import Builder

def build(builder: Builder):
    """Build core_mac_main.dll (Base Tier) - MACs."""
    src_dir = builder.config.src_dir
    
    # Combined sources from all MAC categories
    sources = builder.get_sources([
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
        os.path.join(src_dir, 'primitives/mac/aes_cmac/'),
        os.path.join(src_dir, 'primitives/mac/siphash/'),
        os.path.join(src_dir, 'PQCrypto/common/hkdf/'),
    ], recursive=True)
    
    # Add individual files for SHA2 and FIPS202 (SHA3)
    sources.append(os.path.join(src_dir, 'PQCrypto/common/sha2.c'))
    sources.append(os.path.join(src_dir, 'PQCrypto/common/fips202.c'))
    
    # Common includes
    includes = [
        os.path.join(src_dir, 'primitives/cipher/aes_core'),
        os.path.join(src_dir, 'primitives/mac'),
        os.path.join(src_dir, 'PQCrypto/common'),
        src_dir,
    ]
    
    # Macros
    macros = [
        ('AES___', '128'),
    ]

    return builder.build_target('core_mac_main', sources, 
                                includes=includes,
                                macros=macros,
                                output_subdir='base')

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    log_dir = os.path.dirname(config.get_log_path('base', 'core_mac_main'))
    os.makedirs(log_dir, exist_ok=True)
    
    with Logger(config.get_log_path('base', 'core_mac_main')) as logger:
        build(Builder(config, logger))
