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
    ], recursive=True)
    
    # Add individual files
    sources.append(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/chacha20_poly1305.c'))
    sources.append(os.path.join(src_dir, 'primitives/aead/chacha20_poly1305/monocypher.c'))
    
    sources.append(os.path.join(src_dir, 'PQCrypto/common/sha2.c'))
    sources.append(os.path.join(src_dir, 'PQCrypto/common/fips202.c')) # SHA3/SHAKE for HKDF
    sources.append(os.path.join(src_dir, 'primitives/hash/sponge_xof/shake/shake.c')) # SHAKE256 for Ed448
    sources.append(os.path.join(src_dir, 'utils/drbg/drbg.c')) # CTR_DRBG
    
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

    return builder.build_target('core', sources,
                                includes=includes,
                                macros=macros,
                                output_subdir='main',
                                wasm_exports=_WASM_CORE_EXPORTS)

if __name__ == "__main__":
    from script.core import Config, Logger
    config = Config()
    log_dir = os.path.dirname(config.get_log_path('main', 'core'))
    os.makedirs(log_dir, exist_ok=True)
    
    with Logger(config.get_log_path('main', 'core')) as logger:
        build(Builder(config, logger))
