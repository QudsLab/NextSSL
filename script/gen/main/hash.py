import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import Config, Logger, Builder

_WASM_HASH_EXPORTS = [
    # SHA-2 family (primitive_fast)
    'nextssl_sha256', 'nextssl_sha256_init', 'nextssl_sha256_update', 'nextssl_sha256_final',
    'nextssl_sha512', 'nextssl_sha224', 'nextssl_sha384',
    # BLAKE (primitive_fast)
    'nextssl_blake3',
    'nextssl_blake2b', 'nextssl_blake2s',
    # Argon2 (KDF)
    'nextssl_argon2id', 'nextssl_argon2i', 'nextssl_argon2d',
    # SHA-3 / sponge / XOF (primitive_sponge_xof)
    'nextssl_sha3_224', 'nextssl_sha3_256', 'nextssl_sha3_384', 'nextssl_sha3_512',
    'nextssl_keccak_256',
    'nextssl_shake128', 'nextssl_shake256',
    # Legacy alive (sha1, md5, ripemd160, whirlpool, nt_hash, aes_ecb)
    'nextssl_sha1', 'nextssl_md5',
    'nextssl_ripemd160', 'nextssl_whirlpool',
    'nextssl_nt_hash', 'nextssl_aes_ecb_encrypt',
    # Legacy unsafe (cryptographically broken — backward compat only)
    'nextssl_md2', 'nextssl_md4',
    'nextssl_sha0',
    'nextssl_ripemd128', 'nextssl_ripemd256', 'nextssl_ripemd320',
    'nextssl_has160',
    # Memory allocation — required by Python wasmtime tests in script/web/
    'malloc', 'free',
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
