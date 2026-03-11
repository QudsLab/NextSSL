import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))

from script.core import Config, Logger, Builder

_WASM_HASH_EXPORTS = [
    # SHA-2 family (primitive_fast)
    'sha256', 'sha256_init', 'sha256_update', 'sha256_final',
    'sha512_hash', 'sha224_hash', 'sha384_hash',
    # BLAKE (primitive_fast)
    'blake3_hasher_init', 'blake3_hasher_update', 'blake3_hasher_finalize',
    'blake2b_512_hash', 'blake2s_256_hash',
    # Argon2 (KDF)
    'argon2id_hash_raw', 'argon2i_hash_raw', 'argon2d_hash_raw',
    # SHA-3 / sponge / XOF (primitive_sponge_xof)
    'sha3_224_hash', 'sha3_256_hash', 'sha3_384_hash', 'sha3_512_hash',
    'keccak_256_hash',
    'shake128_hash', 'shake256_hash',
    # Legacy alive (sha1, md5, ripemd160, whirlpool, nt_hash, aes_ecb)
    'sha1_hash', 'md5_hash',
    'ripemd160_hash', 'whirlpool_hash',
    'nt_hash', 'AES_ECB_encrypt',
    # Legacy unsafe (cryptographically broken — backward compat only)
    'md2_hash', 'md4_hash',
    'sha0_hash',
    'ripemd128_hash', 'ripemd256_hash', 'ripemd320_hash',
    'has160_hash',
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
    
    # BLAKE3 SIMD files (avx512, avx2, sse41) require explicit -mavx512f /
    # -mavx2 / -mssse3 compiler flags that the unified build command does not
    # supply.  Without those flags GCC compiles the intrinsics to incorrect
    # machine code (accepted silently but produces wrong hashes at runtime on
    # any CPU that has those ISA extensions).  SSE2 is the x86-64 ABI baseline
    # and is always compiled correctly without extra flags.
    # Solution: exclude the three problematic files from the source list and
    # add the corresponding NO_* macros so blake3_dispatch.c does not reference
    # their (now absent) symbols.
    _blake3_simd_exclude = {'blake3_avx512.c', 'blake3_avx2.c', 'blake3_sse41.c'}
    sources = [s for s in sources
               if os.path.basename(s) not in _blake3_simd_exclude]

    blake3_safe_macros = ['BLAKE3_NO_AVX512', 'BLAKE3_NO_AVX2', 'BLAKE3_NO_SSE41']

    return builder.build_target('hash', sources,
                                extra_libs=['-lpthread'],
                                output_subdir='main',
                                macros=blake3_safe_macros,
                                wasm_exports=_WASM_HASH_EXPORTS)

if __name__ == "__main__":
    config = Config()
    with Logger(config.get_log_path('main', 'hash')) as logger:
        builder = Builder(config, logger)
        build(builder)
