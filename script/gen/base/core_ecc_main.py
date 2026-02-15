import os
from script.core import Builder

def build(builder: Builder):
    """Build core_ecc_main.dll (Base Tier) - ECC."""
    src_dir = builder.config.src_dir
    
    # Combined sources from all ECC categories
    sources = builder.get_sources([
        os.path.join(src_dir, 'primitives/ecc/ed25519/'),
        os.path.join(src_dir, 'primitives/ecc/curve448/'),
        os.path.join(src_dir, 'primitives/ecc/elligator2/'),
        os.path.join(src_dir, 'primitives/ecc/ristretto255/'),
        # Dependencies for CTR_DRBG (used by Curve448)
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
    ], recursive=True)

    # Add individual dependencies
    sources.append(os.path.join(src_dir, 'utils/drbg/drbg.c')) # CTR_DRBG implementation
    sources.append(os.path.join(src_dir, 'primitives/hash/sponge_xof/shake/shake.c')) # SHAKE256 for Ed448
    
    # Common includes
    includes = [
        os.path.join(src_dir, 'primitives/ecc/ed25519'),
        os.path.join(src_dir, 'primitives/ecc/curve448'),
        os.path.join(src_dir, 'primitives/ecc/elligator2'),
        os.path.join(src_dir, 'primitives/ecc/ristretto255'),
        os.path.join(src_dir, 'primitives/cipher/aes_core'), # For AES_internal.h
        os.path.join(src_dir, 'utils/drbg'), # For drbg.h
        os.path.join(src_dir, 'primitives/hash/sponge_xof/shake'), # For shake.h
        src_dir,
    ]
    
    # Macros
    macros = [
        ('HAVE_ED448', '1'),
    ]

    return builder.build_target('core_ecc_main', sources, 
                                includes=includes,
                                macros=macros,
                                output_subdir='base')

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    log_dir = os.path.dirname(config.get_log_path('base', 'core_ecc_main'))
    os.makedirs(log_dir, exist_ok=True)
    
    with Logger(config.get_log_path('base', 'core_ecc_main')) as logger:
        build(Builder(config, logger))
