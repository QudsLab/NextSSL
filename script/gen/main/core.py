import os
from script.core import Builder

_WASM_CORE_EXPORTS = [
    # ── Cipher ──────────────────────────────────────────────────────────────
    # AES-CBC
    'AES_CBC_encrypt', 'AES_CBC_decrypt',
    # AES-CFB
    'AES_CFB_encrypt', 'AES_CFB_decrypt',
    # AES-OFB
    'AES_OFB_encrypt', 'AES_OFB_decrypt',
    # AES-CTR
    'AES_CTR_encrypt', 'AES_CTR_decrypt',
    # AES-XTS (needs double-length key: two AES keys)
    'AES_XTS_encrypt', 'AES_XTS_decrypt',
    # AES Key Wrap (RFC 3394)
    'AES_KEY_wrap', 'AES_KEY_unwrap',
    # AES-FPE (format-preserving)
    'AES_FPE_encrypt', 'AES_FPE_decrypt',
    # AES-ECB (legacy/alive — deterministic, no IV)
    'AES_ECB_encrypt', 'AES_ECB_decrypt',

    # ── AEAD ─────────────────────────────────────────────────────────────────
    'AES_GCM_encrypt', 'AES_GCM_decrypt',
    'AES_CCM_encrypt', 'AES_CCM_decrypt',
    'AES_OCB_encrypt', 'AES_OCB_decrypt',
    'AES_EAX_encrypt', 'AES_EAX_decrypt',
    'AES_SIV_encrypt', 'AES_SIV_decrypt',
    'GCM_SIV_encrypt', 'GCM_SIV_decrypt',
    'AES_Poly1305',
    'ChaCha20_Poly1305_encrypt', 'ChaCha20_Poly1305_decrypt',

    # ── MAC ──────────────────────────────────────────────────────────────────
    'AES_CMAC',
    'siphash',

    # ── HMAC / KDF ───────────────────────────────────────────────────────────
    # HMAC
    'pqc_hmac_sha256',
    'hmac_sha3_256', 'hmac_sha3_512',
    # HKDF-SHA256 (RFC 5869)
    'hkdf_extract', 'hkdf_expand', 'hkdf',
    # HKDF-SHA3-256
    'hkdf_sha3_256_extract', 'hkdf_sha3_256_expand', 'hkdf_sha3_256',
    # HKDF-SHA3-512
    'hkdf_sha3_512_extract', 'hkdf_sha3_512_expand', 'hkdf_sha3_512',
    # TLS 1.3 expand-label (RFC 8446) + SHAKE256-based KDF
    'hkdf_expand_label',
    'kdf_shake256',

    # ── DRBG ─────────────────────────────────────────────────────────────────
    'ctr_drbg_init', 'ctr_drbg_reseed', 'ctr_drbg_generate', 'ctr_drbg_free',

    # ── ECC — Ed25519 ────────────────────────────────────────────────────────
    'ed25519_create_seed',
    'ed25519_create_keypair',
    'ed25519_sign', 'ed25519_verify',
    'ed25519_add_scalar',
    'ed25519_key_exchange',

    # ── ECC — Elligator2 ─────────────────────────────────────────────────────
    'elligator2_map', 'elligator2_rev', 'elligator2_key_pair',

    # ── ECC — Ristretto255 ───────────────────────────────────────────────────
    'ristretto255_is_valid_point',
    'ristretto255_add', 'ristretto255_sub',
    'ristretto255_from_hash',

    # ── ECC — Curve448 (wolfcrypt-style struct API) ───────────────────────────
    'wc_curve448_init', 'wc_curve448_free',
    'wc_curve448_make_key', 'wc_curve448_make_pub',
    'wc_curve448_make_key_deterministic',
    'wc_curve448_shared_secret', 'wc_curve448_shared_secret_ex',
    'wc_curve448_import_private', 'wc_curve448_import_private_ex',
    'wc_curve448_import_private_raw', 'wc_curve448_import_private_raw_ex',
    'wc_curve448_export_private_raw', 'wc_curve448_export_private_raw_ex',
    'wc_curve448_import_public', 'wc_curve448_import_public_ex',
    'wc_curve448_check_public',
    'wc_curve448_export_public', 'wc_curve448_export_public_ex',
    'wc_curve448_export_key_raw', 'wc_curve448_export_key_raw_ex',
    'wc_curve448_size',

    # ── ECC — Ed448 (wolfcrypt-style struct API) ──────────────────────────────
    'wc_ed448_init', 'wc_ed448_init_ex', 'wc_ed448_free',
    'wc_ed448_make_key', 'wc_ed448_make_public',
    'wc_ed448_sign_msg', 'wc_ed448_sign_msg_ex',
    'wc_ed448ph_sign_hash', 'wc_ed448ph_sign_msg',
    'wc_ed448_verify_msg', 'wc_ed448_verify_msg_ex',
    'wc_ed448_verify_msg_init', 'wc_ed448_verify_msg_update', 'wc_ed448_verify_msg_final',
    'wc_ed448ph_verify_hash', 'wc_ed448ph_verify_msg',
    'wc_ed448_import_public', 'wc_ed448_import_public_ex',
    'wc_ed448_import_private_only',
    'wc_ed448_import_private_key', 'wc_ed448_import_private_key_ex',
    'wc_ed448_export_public',
    'wc_ed448_export_private_only', 'wc_ed448_export_private',
    'wc_ed448_export_key',
    'wc_ed448_check_key',
    'wc_ed448_size', 'wc_ed448_priv_size', 'wc_ed448_pub_size', 'wc_ed448_sig_size',

    # Memory allocation — required by Python wasmtime tests in script/web/
    'malloc', 'free',

    # ── Keygen one-shots (src/seed/keygen.c) ─────────────────────────────────
    # ECC — 4 algos × 4 modes = 20
    'keygen_ed25519_random',  'keygen_ed25519_drbg',  'keygen_ed25519_password',  'keygen_ed25519_hd',
    'keygen_x25519_random',   'keygen_x25519_drbg',   'keygen_x25519_password',   'keygen_x25519_hd',
    'keygen_ed448_random',    'keygen_ed448_drbg',    'keygen_ed448_password',    'keygen_ed448_hd',
    'keygen_x448_random',     'keygen_x448_drbg',     'keygen_x448_password',     'keygen_x448_hd',
    'keygen_elligator2_random','keygen_elligator2_drbg','keygen_elligator2_password','keygen_elligator2_hd',
    # ML-KEM — 3 × 4 = 12
    'keygen_ml_kem_512_random',  'keygen_ml_kem_512_drbg',  'keygen_ml_kem_512_password',  'keygen_ml_kem_512_hd',
    'keygen_ml_kem_768_random',  'keygen_ml_kem_768_drbg',  'keygen_ml_kem_768_password',  'keygen_ml_kem_768_hd',
    'keygen_ml_kem_1024_random', 'keygen_ml_kem_1024_drbg', 'keygen_ml_kem_1024_password', 'keygen_ml_kem_1024_hd',
    # ML-DSA — 3 × 4 = 12
    'keygen_ml_dsa_44_random',  'keygen_ml_dsa_44_drbg',  'keygen_ml_dsa_44_password',  'keygen_ml_dsa_44_hd',
    'keygen_ml_dsa_65_random',  'keygen_ml_dsa_65_drbg',  'keygen_ml_dsa_65_password',  'keygen_ml_dsa_65_hd',
    'keygen_ml_dsa_87_random',  'keygen_ml_dsa_87_drbg',  'keygen_ml_dsa_87_password',  'keygen_ml_dsa_87_hd',
    # Falcon — 4 × 4 = 16
    'keygen_falcon_512_random',         'keygen_falcon_512_drbg',         'keygen_falcon_512_password',         'keygen_falcon_512_hd',
    'keygen_falcon_1024_random',        'keygen_falcon_1024_drbg',        'keygen_falcon_1024_password',        'keygen_falcon_1024_hd',
    'keygen_falcon_padded_512_random',  'keygen_falcon_padded_512_drbg',  'keygen_falcon_padded_512_password',  'keygen_falcon_padded_512_hd',
    'keygen_falcon_padded_1024_random', 'keygen_falcon_padded_1024_drbg', 'keygen_falcon_padded_1024_password', 'keygen_falcon_padded_1024_hd',
    # SPHINCS+-SHA2 — 6 × 4 = 24
    'keygen_sphincs_sha2_128f_random',  'keygen_sphincs_sha2_128f_drbg',  'keygen_sphincs_sha2_128f_password',  'keygen_sphincs_sha2_128f_hd',
    'keygen_sphincs_sha2_128s_random',  'keygen_sphincs_sha2_128s_drbg',  'keygen_sphincs_sha2_128s_password',  'keygen_sphincs_sha2_128s_hd',
    'keygen_sphincs_sha2_192f_random',  'keygen_sphincs_sha2_192f_drbg',  'keygen_sphincs_sha2_192f_password',  'keygen_sphincs_sha2_192f_hd',
    'keygen_sphincs_sha2_192s_random',  'keygen_sphincs_sha2_192s_drbg',  'keygen_sphincs_sha2_192s_password',  'keygen_sphincs_sha2_192s_hd',
    'keygen_sphincs_sha2_256f_random',  'keygen_sphincs_sha2_256f_drbg',  'keygen_sphincs_sha2_256f_password',  'keygen_sphincs_sha2_256f_hd',
    'keygen_sphincs_sha2_256s_random',  'keygen_sphincs_sha2_256s_drbg',  'keygen_sphincs_sha2_256s_password',  'keygen_sphincs_sha2_256s_hd',
    # SPHINCS+-SHAKE — 6 × 4 = 24
    'keygen_sphincs_shake_128f_random', 'keygen_sphincs_shake_128f_drbg', 'keygen_sphincs_shake_128f_password', 'keygen_sphincs_shake_128f_hd',
    'keygen_sphincs_shake_128s_random', 'keygen_sphincs_shake_128s_drbg', 'keygen_sphincs_shake_128s_password', 'keygen_sphincs_shake_128s_hd',
    'keygen_sphincs_shake_192f_random', 'keygen_sphincs_shake_192f_drbg', 'keygen_sphincs_shake_192f_password', 'keygen_sphincs_shake_192f_hd',
    'keygen_sphincs_shake_192s_random', 'keygen_sphincs_shake_192s_drbg', 'keygen_sphincs_shake_192s_password', 'keygen_sphincs_shake_192s_hd',
    'keygen_sphincs_shake_256f_random', 'keygen_sphincs_shake_256f_drbg', 'keygen_sphincs_shake_256f_password', 'keygen_sphincs_shake_256f_hd',
    'keygen_sphincs_shake_256s_random', 'keygen_sphincs_shake_256s_drbg', 'keygen_sphincs_shake_256s_password', 'keygen_sphincs_shake_256s_hd',
    # HQC — 3 × 4 = 12
    'keygen_hqc_128_random',  'keygen_hqc_128_drbg',  'keygen_hqc_128_password',  'keygen_hqc_128_hd',
    'keygen_hqc_192_random',  'keygen_hqc_192_drbg',  'keygen_hqc_192_password',  'keygen_hqc_192_hd',
    'keygen_hqc_256_random',  'keygen_hqc_256_drbg',  'keygen_hqc_256_password',  'keygen_hqc_256_hd',
    # McEliece — 10 × 4 = 40
    'keygen_mceliece_348864_random',   'keygen_mceliece_348864_drbg',   'keygen_mceliece_348864_password',   'keygen_mceliece_348864_hd',
    'keygen_mceliece_348864f_random',  'keygen_mceliece_348864f_drbg',  'keygen_mceliece_348864f_password',  'keygen_mceliece_348864f_hd',
    'keygen_mceliece_460896_random',   'keygen_mceliece_460896_drbg',   'keygen_mceliece_460896_password',   'keygen_mceliece_460896_hd',
    'keygen_mceliece_460896f_random',  'keygen_mceliece_460896f_drbg',  'keygen_mceliece_460896f_password',  'keygen_mceliece_460896f_hd',
    'keygen_mceliece_6688128_random',  'keygen_mceliece_6688128_drbg',  'keygen_mceliece_6688128_password',  'keygen_mceliece_6688128_hd',
    'keygen_mceliece_6688128f_random', 'keygen_mceliece_6688128f_drbg', 'keygen_mceliece_6688128f_password', 'keygen_mceliece_6688128f_hd',
    'keygen_mceliece_6960119_random',  'keygen_mceliece_6960119_drbg',  'keygen_mceliece_6960119_password',  'keygen_mceliece_6960119_hd',
    'keygen_mceliece_6960119f_random', 'keygen_mceliece_6960119f_drbg', 'keygen_mceliece_6960119f_password', 'keygen_mceliece_6960119f_hd',
    'keygen_mceliece_8192128_random',  'keygen_mceliece_8192128_drbg',  'keygen_mceliece_8192128_password',  'keygen_mceliece_8192128_hd',
    'keygen_mceliece_8192128f_random', 'keygen_mceliece_8192128f_drbg', 'keygen_mceliece_8192128f_password', 'keygen_mceliece_8192128f_hd',
]

def build(builder: Builder):
    """Build core.dll (Main Tier) - Complete Classic Crypto Suite."""
    src_dir = builder.config.src_dir
    
    # Combined sources from ALL core categories
    sources = builder.get_sources([
        # Cipher
        os.path.join(src_dir, 'primitives/cipher/aes_core/'),
        os.path.join(src_dir, 'legacy/alive/aes_ecb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cbc/'),
        os.path.join(src_dir, 'primitives/cipher/aes_cfb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ofb/'),
        os.path.join(src_dir, 'primitives/cipher/aes_ctr/'),
        os.path.join(src_dir, 'primitives/cipher/aes_xts/'),
        os.path.join(src_dir, 'primitives/cipher/aes_kw/'),
        os.path.join(src_dir, 'primitives/cipher/aes_fpe/'),
        
        # AEAD
        os.path.join(src_dir, 'primitives/aead/aes_gcm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ccm/'),
        os.path.join(src_dir, 'primitives/aead/aes_ocb/'),
        os.path.join(src_dir, 'primitives/aead/aes_eax/'),
        os.path.join(src_dir, 'primitives/aead/aes_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_gcm_siv/'),
        os.path.join(src_dir, 'primitives/aead/aes_poly1305/'),
        # os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/'), # Handled below to exclude optional
        
        # MAC
        os.path.join(src_dir, 'primitives/mac/aes_cmac/'),
        os.path.join(src_dir, 'primitives/mac/siphash/'),
        os.path.join(src_dir, 'PQCrypto/common/hkdf/'),
        
        # ECC
        os.path.join(src_dir, 'primitives/ecc/ed25519/'),
        os.path.join(src_dir, 'primitives/ecc/curve448/'),
        os.path.join(src_dir, 'primitives/ecc/elligator2/'),
        os.path.join(src_dir, 'primitives/ecc/ristretto255/'),
        # Keygen one-shot system (all 160 keygen_*_mode functions)
        os.path.join(src_dir, 'seed/'),
        # Hash primitives needed by seed/ layer:
        #   seed/hash/seed_hash.c   → primitives/hash/fast/sha512/
        #   seed/password/seed_password.c → primitives/hash/memory_hard/ (Argon2id)
        os.path.join(src_dir, 'primitives/hash/fast/sha512/'),
        os.path.join(src_dir, 'primitives/hash/memory_hard/'),
    ], recursive=True)
    
    # Add individual files
    sources.append(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/chacha20_poly1305.c'))
    sources.append(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/monocypher.c'))
    
    sources.append(os.path.join(src_dir, 'PQCrypto/common/sha2.c'))
    sources.append(os.path.join(src_dir, 'PQCrypto/common/fips202.c')) # SHA3/SHAKE for HKDF
    sources.append(os.path.join(src_dir, 'primitives/hash/sponge_xof/shake/shake.c')) # SHAKE256 for Ed448
    # NOTE: CTR_DRBG (seed/drbg/drbg.c) is already included through the seed/ recursive scan above.
    # Do NOT add utils/drbg/drbg.c here — that path does not exist.

    # Add wrapper if it exists
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
        os.path.join(src_dir, 'primitives/ecc/ed25519'),
        os.path.join(src_dir, 'primitives/ecc/curve448'),
        os.path.join(src_dir, 'primitives/ecc/elligator2'),
        os.path.join(src_dir, 'primitives/ecc/ristretto255'),
        os.path.join(src_dir, 'PQCrypto/common'),
        os.path.join(src_dir, 'primitives/hash/sponge_xof/shake'), # For shake.h
        src_dir,
    ]
    
    # Macros
    macros = [
        ('AES___', '128'),
        ('FF_X', '1'),
        ('HAVE_ED448', '1'),
    ]

    # core.dll keygen PQC functions call pqc_*_keypair_derand which live in pqc.dll.
    # Link against pqc.dll so those symbols resolve at load time.
    # Also need -lbcrypt for seed/rng/rng.c (BCryptGenRandom on Windows).
    extra_libs = []
    lib_ext = builder.config.get_shared_lib_ext()
    if lib_ext != '.wasm':
        pqc_lib = builder.config.get_lib_path('main', 'pqc')
        if not os.path.exists(pqc_lib):
            builder.logger.error(f"pqc.dll not found at {pqc_lib} — build pqc before core")
            return False
        extra_libs.append(pqc_lib)
        extra_libs.append('-lbcrypt')

    return builder.build_target('core', sources,
                                includes=includes,
                                macros=macros,
                                extra_libs=extra_libs if extra_libs else None,
                                output_subdir='main',
                                wasm_exports=_WASM_CORE_EXPORTS)

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    log_dir = os.path.dirname(config.get_log_path('main', 'core'))
    os.makedirs(log_dir, exist_ok=True)
    
    with Logger(config.get_log_path('main', 'core')) as logger:
        build(Builder(config, logger))
