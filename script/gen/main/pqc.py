import os
from script.core import Builder, Config, Logger

_WASM_PQC_EXPORTS = [
    # ── KEM: ML-KEM ──────────────────────────────────────────────────────────
    'pqc_mlkem512_keypair',          'pqc_mlkem512_keypair_derand',
    'pqc_mlkem512_encaps',           'pqc_mlkem512_encaps_derand',
    'pqc_mlkem512_decaps',
    'pqc_mlkem768_keypair',          'pqc_mlkem768_keypair_derand',
    'pqc_mlkem768_encaps',           'pqc_mlkem768_encaps_derand',
    'pqc_mlkem768_decaps',
    'pqc_mlkem1024_keypair',         'pqc_mlkem1024_keypair_derand',
    'pqc_mlkem1024_encaps',          'pqc_mlkem1024_encaps_derand',
    'pqc_mlkem1024_decaps',
    # ── KEM: HQC ─────────────────────────────────────────────────────────────
    'pqc_hqc128_keypair',            'pqc_hqc128_keypair_derand',
    'pqc_hqc128_encaps',             'pqc_hqc128_encaps_derand',
    'pqc_hqc128_decaps',
    'pqc_hqc192_keypair',            'pqc_hqc192_keypair_derand',
    'pqc_hqc192_encaps',             'pqc_hqc192_encaps_derand',
    'pqc_hqc192_decaps',
    'pqc_hqc256_keypair',            'pqc_hqc256_keypair_derand',
    'pqc_hqc256_encaps',             'pqc_hqc256_encaps_derand',
    'pqc_hqc256_decaps',
    # ── KEM: McEliece — intentionally excluded from web ──────────────────────
    # McEliece public keys are 256 KB – 1.3 MB; impractical in a browser
    # context. All 10 McEliece variants remain in pqc.dll / .so / .dylib but
    # are dead-stripped from pqc.wasm to keep the binary usable.
    # ── Sign: ML-DSA ─────────────────────────────────────────────────────────
    'pqc_mldsa44_keypair',           'pqc_mldsa44_keypair_derand',
    'pqc_mldsa44_sign',              'pqc_mldsa44_sign_derand',
    'pqc_mldsa44_verify',
    'pqc_mldsa65_keypair',           'pqc_mldsa65_keypair_derand',
    'pqc_mldsa65_sign',              'pqc_mldsa65_sign_derand',
    'pqc_mldsa65_verify',
    'pqc_mldsa87_keypair',           'pqc_mldsa87_keypair_derand',
    'pqc_mldsa87_sign',              'pqc_mldsa87_sign_derand',
    'pqc_mldsa87_verify',
    # ── Sign: Falcon (standard + padded) ─────────────────────────────────────
    'pqc_falcon512_keypair',         'pqc_falcon512_keypair_derand',
    'pqc_falcon512_sign',            'pqc_falcon512_sign_derand',
    'pqc_falcon512_verify',
    'pqc_falcon1024_keypair',        'pqc_falcon1024_keypair_derand',
    'pqc_falcon1024_sign',           'pqc_falcon1024_sign_derand',
    'pqc_falcon1024_verify',
    'pqc_falconpadded512_keypair',   'pqc_falconpadded512_keypair_derand',
    'pqc_falconpadded512_sign',      'pqc_falconpadded512_sign_derand',
    'pqc_falconpadded512_verify',
    'pqc_falconpadded1024_keypair',  'pqc_falconpadded1024_keypair_derand',
    'pqc_falconpadded1024_sign',     'pqc_falconpadded1024_sign_derand',
    'pqc_falconpadded1024_verify',
    # ── Sign: SPHINCS+ (SHA-2 and SHAKE, all 12 variants) ────────────────────
    'pqc_sphincssha2128fsimple_keypair',  'pqc_sphincssha2128fsimple_keypair_derand',
    'pqc_sphincssha2128fsimple_sign',     'pqc_sphincssha2128fsimple_sign_derand',
    'pqc_sphincssha2128fsimple_verify',
    'pqc_sphincssha2128ssimple_keypair',  'pqc_sphincssha2128ssimple_keypair_derand',
    'pqc_sphincssha2128ssimple_sign',     'pqc_sphincssha2128ssimple_sign_derand',
    'pqc_sphincssha2128ssimple_verify',
    'pqc_sphincssha2192fsimple_keypair',  'pqc_sphincssha2192fsimple_keypair_derand',
    'pqc_sphincssha2192fsimple_sign',     'pqc_sphincssha2192fsimple_sign_derand',
    'pqc_sphincssha2192fsimple_verify',
    'pqc_sphincssha2192ssimple_keypair',  'pqc_sphincssha2192ssimple_keypair_derand',
    'pqc_sphincssha2192ssimple_sign',     'pqc_sphincssha2192ssimple_sign_derand',
    'pqc_sphincssha2192ssimple_verify',
    'pqc_sphincssha2256fsimple_keypair',  'pqc_sphincssha2256fsimple_keypair_derand',
    'pqc_sphincssha2256fsimple_sign',     'pqc_sphincssha2256fsimple_sign_derand',
    'pqc_sphincssha2256fsimple_verify',
    'pqc_sphincssha2256ssimple_keypair',  'pqc_sphincssha2256ssimple_keypair_derand',
    'pqc_sphincssha2256ssimple_sign',     'pqc_sphincssha2256ssimple_sign_derand',
    'pqc_sphincssha2256ssimple_verify',
    'pqc_sphincsshake128fsimple_keypair', 'pqc_sphincsshake128fsimple_keypair_derand',
    'pqc_sphincsshake128fsimple_sign',    'pqc_sphincsshake128fsimple_sign_derand',
    'pqc_sphincsshake128fsimple_verify',
    'pqc_sphincsshake128ssimple_keypair', 'pqc_sphincsshake128ssimple_keypair_derand',
    'pqc_sphincsshake128ssimple_sign',    'pqc_sphincsshake128ssimple_sign_derand',
    'pqc_sphincsshake128ssimple_verify',
    'pqc_sphincsshake192fsimple_keypair', 'pqc_sphincsshake192fsimple_keypair_derand',
    'pqc_sphincsshake192fsimple_sign',    'pqc_sphincsshake192fsimple_sign_derand',
    'pqc_sphincsshake192fsimple_verify',
    'pqc_sphincsshake192ssimple_keypair', 'pqc_sphincsshake192ssimple_keypair_derand',
    'pqc_sphincsshake192ssimple_sign',    'pqc_sphincsshake192ssimple_sign_derand',
    'pqc_sphincsshake192ssimple_verify',
    'pqc_sphincsshake256fsimple_keypair', 'pqc_sphincsshake256fsimple_keypair_derand',
    'pqc_sphincsshake256fsimple_sign',    'pqc_sphincsshake256fsimple_sign_derand',
    'pqc_sphincsshake256fsimple_verify',
    'pqc_sphincsshake256ssimple_keypair', 'pqc_sphincsshake256ssimple_keypair_derand',
    'pqc_sphincsshake256ssimple_sign',    'pqc_sphincsshake256ssimple_sign_derand',
    'pqc_sphincsshake256ssimple_verify',
    # ── Util ─────────────────────────────────────────────────────────────────
    'pqc_randombytes', 'pqc_set_mode',
    'pqc_drbg_seed', 'pqc_drbg_reseed',
    # Memory allocation — required by Python wasmtime tests in script/web/
    'malloc', 'free',
]

def build(builder: Builder):
    """Build pqc.dll with ALL PQC algorithms."""
    src_dir = builder.config.src_dir
    
    # ── KEM ──
    kem_lattice_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-768/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/ml-kem-1024/clean/'),
    ]
    hqc_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_kem/hqc-128/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/hqc-192/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/hqc-256/clean/'),
    ]
    mceliece_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece348864/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece348864f/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece460896/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece460896f/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece6688128/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece6688128f/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece6960119/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece6960119f/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece8192128/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_kem/mceliece8192128f/clean/'),
    ]
    
    # ── SIGN ──
    mldsa_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-44/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-65/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/ml-dsa-87/clean/'),
    ]
    falcon_dirs = [
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-1024/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-padded-512/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/falcon-padded-1024/clean/'),
    ]
    sphincs_dirs = [
        # SHA2 variants
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-128f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-128s-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-192f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-192s-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-256f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-sha2-256s-simple/clean/'),
        # SHAKE variants
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-128f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-128s-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-192f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-192s-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-256f-simple/clean/'),
        os.path.join(src_dir, 'PQCrypto/crypto_sign/sphincs-shake-256s-simple/clean/'),
    ]
    
    all_dirs = kem_lattice_dirs + hqc_dirs + mceliece_dirs + mldsa_dirs + falcon_dirs + sphincs_dirs
    sources = builder.get_sources(all_dirs, recursive=True)
    
    # Add shared randomness layer
    common_files = builder.get_sources([
        os.path.join(src_dir, 'PQCrypto/common'),
        os.path.join(src_dir, 'PQCrypto/common/drbg'),
        os.path.join(src_dir, 'PQCrypto/common/hkdf'),
    ], recursive=False)
    sources.extend(common_files)
    
    # Add wrapper
    wrapper = os.path.join(src_dir, 'utils/pqc_main.c')
    if os.path.exists(wrapper):
        sources.append(wrapper)
    else:
        builder.logger.error(f"Wrapper not found: {wrapper}")
        return False

    # Additional includes for PQC
    includes = [
        os.path.join(src_dir, 'PQCrypto'),
        os.path.join(src_dir, 'PQCrypto', 'common'),
    ]
    includes.extend(all_dirs)

    return builder.build_target(
        'pqc',
        sources,
        output_subdir='main',
        macros=[
            'ENABLE_ML_KEM', 'ENABLE_HQC', 'ENABLE_MCELIECE',
            'ENABLE_ML_DSA', 'ENABLE_FALCON', 'ENABLE_SPHINCS'
        ],
        remove_macros=['EXCLUDE_SPHINCS'],
        includes=includes,
        wasm_exports=_WASM_PQC_EXPORTS
    )

if __name__ == "__main__":
    # Allow standalone execution (for debugging)
    config = Config()
    with Logger(config.get_log_path('main', 'pqc')) as logger:
        build(Builder(config, logger))
