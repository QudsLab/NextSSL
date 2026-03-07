import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import Config, Logger, Builder

_WASM_HASH_EXPORTS = [
    'nextssl_sha256', 'nextssl_sha256_init', 'nextssl_sha256_update', 'nextssl_sha256_final',
    'nextssl_sha512', 'nextssl_sha224', 'nextssl_sha384',
    'nextssl_blake3',
    'nextssl_argon2id', 'nextssl_argon2i', 'nextssl_argon2d',
    'nextssl_sha3_256', 'nextssl_sha3_512',
    'nextssl_keccak256',
    'nextssl_shake128', 'nextssl_shake256',
    'nextssl_sha1', 'nextssl_md5',
    'nextssl_md2', 'nextssl_md4',
]

def build(builder: Builder):
    """Build hash.dll (Main Tier)."""
    src_dir = builder.config.src_dir
    
    # Combined sources from everything
    sources = builder.get_sources([
        os.path.join(src_dir, 'primitives', 'hash'),
        os.path.join(src_dir, 'legacy'),
        os.path.join(src_dir, 'primitives', 'cipher', 'aes_core')
    ], recursive=True)
    
    # All wrappers in utils/hash
    wrappers = builder.get_sources([
        os.path.join(src_dir, 'utils', 'hash')
    ], recursive=False) # Non-recursive to just get the wrappers
    
    sources.extend(wrappers)
            
    return builder.build_target('hash', sources, 
                                extra_libs=['-lpthread'], 
                                output_subdir='main',
                                wasm_exports=_WASM_HASH_EXPORTS)

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main', 'hash')) as logger:
        builder = Builder(config, logger)
        build(builder)
