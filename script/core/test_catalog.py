"""
script/core/test_catalog.py
────────────────────────────
Single source of truth for the three test-mode maps used by
--quickTest, --fullTest, and --hyperTest in runner.py.

Map structure
─────────────
TEST_CATALOG  — master registry; dot-separated IDs → description
QUICK_MAP     — symbol / file-size checks (no execution)
FULL_MAP      — full execution, each algo tested once in its home layer
HYPER_EXTRAS  — additional cross-layer entries added on top of FULL_MAP
HYPER_MAP     — FULL_MAP | HYPER_EXTRAS  (constructed at module load)
"""

# ─────────────────────────────────────────────────────────────────────────────
# Map 1 — TEST_CATALOG
# ─────────────────────────────────────────────────────────────────────────────

TEST_CATALOG = {
    # ── main / hash ──────────────────────────────────────────────────────────
    'hash.sha256':            'SHA-256 KAT  (abc → ba7816…)',
    'hash.sha512':            'SHA-512 KAT',
    'hash.blake3':            'BLAKE3 KAT',
    'hash.argon2id':          'Argon2id  t=1 m=16 p=1',
    'hash.argon2i':           'Argon2i',
    'hash.argon2d':           'Argon2d',
    'hash.sha3_256':          'SHA3-256 KAT',
    'hash.sha3_512':          'SHA3-512 KAT',
    'hash.keccak256':         'Keccak-256 KAT',
    'hash.shake128':          'SHAKE128 XOF',
    'hash.shake256':          'SHAKE256 XOF',
    'hash.sha1':              'SHA-1  (legacy-alive)',
    'hash.md5':               'MD5    (legacy-alive)',
    'hash.md2':               'MD2    (legacy-unsafe)',
    'hash.md4':               'MD4    (legacy-unsafe)',

    # ── main / core ──────────────────────────────────────────────────────────
    'core.aes_cbc':           'AES-CBC NIST KAT',
    'core.aes_gcm':           'AES-GCM empty-message tag',
    'core.chacha20':          'ChaCha20-Poly1305 symbol accessible',
    'core.ed25519':           'Ed25519 sign / verify round-trip',

    # ── main / pqc ───────────────────────────────────────────────────────────
    'pqc.mlkem768':           'ML-KEM-768 keypair / encaps / decaps  (ss match)',
    'pqc.mldsa44':            'ML-DSA-44  keypair / sign / verify',

    # ── main / pow  (single merged DLL after job-002) ────────────────────────
    'pow.sha256':             'PoW SHA-256     primitive_fast family  (d=8)',
    'pow.argon2id':           'PoW Argon2id    primitive_memory_hard  (d=4)',
    'pow.sha3':               'PoW SHA3-256    primitive_sponge_xof   (d=8)',
    'pow.sha1_md5':           'PoW SHA-1/MD5   legacy_alive           (d=8)',
    'pow.md2_md4':            'PoW MD2/MD4     legacy_unsafe          (d=8)',
    'pow.dhcm_sha256':        'DHCM SHA-256    challenge/verify',
    'pow.dhcm_argon2id':      'DHCM Argon2id   challenge/verify',
    'pow.dhcm_sha3':          'DHCM SHA3-256   challenge/verify',
    'pow.dhcm_md5':           'DHCM MD5        challenge/verify',
    'pow.dhcm_md2':           'DHCM MD2        challenge/verify',

    # ── main / keygen  (one-shot keygen modes — all 40 algos × 4 modes) ──────
    'keygen.ed25519':         'keygen_ed25519  random/drbg/password/hd',
    'keygen.x25519':          'keygen_x25519   random/drbg/password/hd',
    'keygen.ed448':           'keygen_ed448    random/drbg/password/hd',
    'keygen.x448':            'keygen_x448     random/drbg/password/hd',
    'keygen.elligator2':      'keygen_elligator2 random/drbg/password/hd',
    'keygen.mlkem512':        'keygen_ml_kem_512   × 4 modes',
    'keygen.mlkem768':        'keygen_ml_kem_768   × 4 modes',
    'keygen.mlkem1024':       'keygen_ml_kem_1024  × 4 modes',
    'keygen.mldsa44':         'keygen_ml_dsa_44    × 4 modes',
    'keygen.mldsa65':         'keygen_ml_dsa_65    × 4 modes',
    'keygen.mldsa87':         'keygen_ml_dsa_87    × 4 modes',
    'keygen.falcon512':       'keygen_falcon_512          × 4 modes',
    'keygen.falcon1024':      'keygen_falcon_1024         × 4 modes',
    'keygen.falconpadded512': 'keygen_falcon_padded_512   × 4 modes',
    'keygen.falconpadded1024':'keygen_falcon_padded_1024  × 4 modes',
    'keygen.sphincssha2128f': 'keygen_sphincs_sha2_128f   × 4 modes',
    'keygen.sphincssha2128s': 'keygen_sphincs_sha2_128s   × 4 modes',
    'keygen.sphincssha2192f': 'keygen_sphincs_sha2_192f   × 4 modes',
    'keygen.sphincssha2192s': 'keygen_sphincs_sha2_192s   × 4 modes',
    'keygen.sphincssha2256f': 'keygen_sphincs_sha2_256f   × 4 modes',
    'keygen.sphincssha2256s': 'keygen_sphincs_sha2_256s   × 4 modes',
    'keygen.sphincsshake128f':'keygen_sphincs_shake_128f  × 4 modes',
    'keygen.sphincsshake128s':'keygen_sphincs_shake_128s  × 4 modes',
    'keygen.sphincsshake192f':'keygen_sphincs_shake_192f  × 4 modes',
    'keygen.sphincsshake192s':'keygen_sphincs_shake_192s  × 4 modes',
    'keygen.sphincsshake256f':'keygen_sphincs_shake_256f  × 4 modes',
    'keygen.sphincsshake256s':'keygen_sphincs_shake_256s  × 4 modes',
    'keygen.hqc128':          'keygen_hqc_128  × 4 modes',
    'keygen.hqc192':          'keygen_hqc_192  × 4 modes',
    'keygen.hqc256':          'keygen_hqc_256  × 4 modes',
    'keygen.mceliece348864':  'keygen_mceliece_348864    × 4 modes',
    'keygen.mceliece348864f': 'keygen_mceliece_348864f   × 4 modes',
    'keygen.mceliece460896':  'keygen_mceliece_460896    × 4 modes',
    'keygen.mceliece460896f': 'keygen_mceliece_460896f   × 4 modes',
    'keygen.mceliece6688128': 'keygen_mceliece_6688128   × 4 modes',
    'keygen.mceliece6688128f':'keygen_mceliece_6688128f  × 4 modes',
    'keygen.mceliece6960119': 'keygen_mceliece_6960119   × 4 modes',
    'keygen.mceliece6960119f':'keygen_mceliece_6960119f  × 4 modes',
    'keygen.mceliece8192128': 'keygen_mceliece_8192128   × 4 modes',
    'keygen.mceliece8192128f':'keygen_mceliece_8192128f  × 4 modes',

    # ── primary / system_lite ─────────────────────────────────────────────────
    'lite.hash':              'nextssl_hash (SHA-256 dispatch)',
    'lite.encrypt':           'nextssl_encrypt / decrypt  (AES-256-GCM)',
    'lite.password':          'nextssl_password_hash / verify  (Argon2id)',
    'lite.keygen':            'nextssl_keygen / keyexchange  (X25519)',
    'lite.sign':              'nextssl_sign / verify  (Ed25519)',
    'lite.pow':               'nextssl_pow_solve / verify',
    'lite.init':              'nextssl_init(MODERN) + nextssl_init(PQC)  dispatch',
    'lite.init_custom':       'nextssl_init_custom + security_level "custom"',
    'lite.version':           'nextssl_version() returns expected string',
    'lite.variant':           'nextssl_variant() == "lite"',
    'lite.has_algo':          'nextssl_has_algorithm  (known + unknown)',
    'lite.hash_ex':           'nextssl_hash_ex  (SHA-512)',
    'lite.encrypt_ex':        'nextssl_encrypt_ex / decrypt_ex  (ChaCha20-Poly1305)',
    'lite.idempotent':        'nextssl_init second call is idempotent',
    'lite.root_hash':         'nextssl_root_hash_sha256 + blake3  KAT',
    'lite.root_hash_rest':    'nextssl_root_hash_sha512 + argon2id  KAT',
    'lite.root_aead':         'nextssl_root_aead_aesgcm + chacha20  round-trip',
    'lite.root_aead_aad':     'nextssl_root_aead  encrypt/decrypt with AAD',
    'lite.root_ecc_ed':       'nextssl_root_ecc_ed25519  keygen/sign/verify',
    'lite.root_ecc_x':        'nextssl_root_ecc_x25519   keygen/exchange',
    'lite.root_pqc_kem':      'nextssl_root_pqc_kem_mlkem1024  keygen/encaps/decaps',
    'lite.root_pqc_sign':     'nextssl_root_pqc_sign_mldsa87   keygen/sign/verify',
    'lite.root_pow':          'nextssl_root_pow  challenge/solve/verify  (d=4)',

    # ── primary / system (full) ───────────────────────────────────────────────
    'system.sha256':          'nextssl_sha256  KAT via primary DLL',
    'system.dhcm':            'nextssl_dhcm_expected_trials  returns > 0',
    'system.pow':             'nextssl_root_pow  challenge/solve/verify  (d=4)',
    'system.pqc_symbols':     'All PQC symbol names accessible in primary DLL',
    'system.aes_cbc':         'AES-CBC direct call via primary DLL',
    'system.init':            'nextssl_init(MODERN) + nextssl_hash  dispatch',
    'system.encrypt':         'nextssl_encrypt / decrypt  round-trip',
    'system.init_custom':     'nextssl_init_custom + security_level "custom"',
    'system.root_hash':       'nextssl_root_hash  sha256/sha512/blake3/sha3  KAT',
    'system.root_legacy':     'nextssl_root_legacy_alive  sha1 + md5  KAT',
    'system.root_aead':       'nextssl_root_aead  AES-GCM + ChaCha20  round-trip',
    'system.root_ecc_ed':     'nextssl_root_ecc_ed25519  sign/verify',
    'system.root_ecc_x':      'nextssl_root_ecc_x25519   ECDH round-trip',
    'system.root_pqc_kem':    'nextssl_root_pqc_kem_mlkem768  keygen/encaps/decaps',
    'system.root_pqc_sign65': 'nextssl_root_pqc_sign_mldsa65  keygen/sign/verify',
    'system.root_pqc_sign87': 'nextssl_root_pqc_sign_mldsa87  keygen/sign/verify',
    'system.root_argon2':     'nextssl_root_hash_argon2id  round-trip',

    # ── wasm (platform=web) ───────────────────────────────────────────────────
    'wasm.hash_present':      'bin/web/main/hash.wasm   exists & size > 512 B',
    'wasm.hash_kat':          'hash.wasm   — all 18 algo KATs  (Python/wasmtime)',
    'wasm.core_kat':          'core.wasm   — AES/ChaCha/HMAC/Ed25519 KATs',
    'wasm.pqc_kat':           'pqc.wasm    — ML-KEM + HQC + ML-DSA + Falcon round-trips',
    'wasm.pow_kat':           'pow.wasm    — PoW challenge/solve/verify  (d=4)',
    'wasm.dhcm_kat':          'dhcm.wasm   — DHCM expected_trials/calculate/info KATs',
    'wasm.system_kat':        'main.wasm   — DHCM cost model  (expected_trials/calculate/info)',
    'wasm.lite_kat':          'main_lite.wasm — lite high-level + root layer KATs',
    'wasm.core_present':      'bin/web/main/core.wasm   exists & size > 512 B',
    'wasm.pqc_present':       'bin/web/main/pqc.wasm    exists & size > 512 B',
    'wasm.pow_present':       'bin/web/main/pow.wasm    exists & size > 512 B',
    'wasm.dhcm_present':      'bin/web/main/dhcm.wasm   exists & size > 512 B',
    'wasm.main_present':      'bin/web/primary/main.wasm       exists & size > 512 B',
    'wasm.main_lite_present': 'bin/web/primary/main_lite.wasm  exists & size > 512 B',
    'wasm.hash_selftest':     'wasmtime hash.wasm    → nextssl_wasm_selftest == 0',
    'wasm.core_selftest':     'wasmtime core.wasm    → nextssl_wasm_selftest == 0',
    'wasm.pqc_selftest':      'wasmtime pqc.wasm     → nextssl_wasm_selftest == 0',
    'wasm.pow_selftest':      'wasmtime pow.wasm     → nextssl_wasm_selftest == 0',
    'wasm.dhcm_selftest':     'wasmtime dhcm.wasm    → nextssl_wasm_selftest == 0',
    'wasm.main_selftest':     'wasmtime main.wasm    → nextssl_wasm_selftest == 0',
    'wasm.main_lite_selftest':'wasmtime main_lite.wasm → nextssl_wasm_selftest == 0',
}

# ─────────────────────────────────────────────────────────────────────────────
# Map 2 — QUICK_MAP
# Symbol / file-size presence checks only.  No algorithm is executed.
# ─────────────────────────────────────────────────────────────────────────────

QUICK_MAP = {
    # ── main/hash ─────────────────────────────────────────────────────────────
    'hash.sha256':            {'layer': 'main/hash',           'check': 'symbol'},
    'hash.sha512':            {'layer': 'main/hash',           'check': 'symbol'},
    'hash.blake3':            {'layer': 'main/hash',           'check': 'symbol'},
    'hash.argon2id':          {'layer': 'main/hash',           'check': 'symbol'},
    'hash.argon2i':           {'layer': 'main/hash',           'check': 'symbol'},
    'hash.argon2d':           {'layer': 'main/hash',           'check': 'symbol'},
    'hash.sha3_256':          {'layer': 'main/hash',           'check': 'symbol'},
    'hash.sha3_512':          {'layer': 'main/hash',           'check': 'symbol'},
    'hash.keccak256':         {'layer': 'main/hash',           'check': 'symbol'},
    'hash.shake128':          {'layer': 'main/hash',           'check': 'symbol'},
    'hash.shake256':          {'layer': 'main/hash',           'check': 'symbol'},
    'hash.sha1':              {'layer': 'main/hash',           'check': 'symbol'},
    'hash.md5':               {'layer': 'main/hash',           'check': 'symbol'},
    'hash.md2':               {'layer': 'main/hash',           'check': 'symbol'},
    'hash.md4':               {'layer': 'main/hash',           'check': 'symbol'},

    # ── main/core ─────────────────────────────────────────────────────────────
    'core.aes_cbc':           {'layer': 'main/core',           'check': 'symbol'},
    'core.aes_gcm':           {'layer': 'main/core',           'check': 'symbol'},
    'core.chacha20':          {'layer': 'main/core',           'check': 'symbol'},
    'core.ed25519':           {'layer': 'main/core',           'check': 'symbol'},

    # ── main/pqc ──────────────────────────────────────────────────────────────
    'pqc.mlkem768':           {'layer': 'main/pqc',            'check': 'symbol'},
    'pqc.mldsa44':            {'layer': 'main/pqc',            'check': 'symbol'},

    # ── main/pow ──────────────────────────────────────────────────────────────
    'pow.sha256':             {'layer': 'main/pow',            'check': 'symbol'},
    'pow.argon2id':           {'layer': 'main/pow',            'check': 'symbol'},
    'pow.sha3':               {'layer': 'main/pow',            'check': 'symbol'},
    'pow.sha1_md5':           {'layer': 'main/pow',            'check': 'symbol'},
    'pow.md2_md4':            {'layer': 'main/pow',            'check': 'symbol'},
    'pow.dhcm_sha256':        {'layer': 'main/pow',            'check': 'symbol'},
    'pow.dhcm_argon2id':      {'layer': 'main/pow',            'check': 'symbol'},
    'pow.dhcm_sha3':          {'layer': 'main/pow',            'check': 'symbol'},
    'pow.dhcm_md5':           {'layer': 'main/pow',            'check': 'symbol'},
    'pow.dhcm_md2':           {'layer': 'main/pow',            'check': 'symbol'},

    # ── main/keygen ───────────────────────────────────────────────────────────
    'keygen.ed25519':         {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.x25519':          {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.ed448':           {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.x448':            {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.elligator2':      {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mlkem512':        {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mlkem768':        {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mlkem1024':       {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mldsa44':         {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mldsa65':         {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mldsa87':         {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.falcon512':       {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.falcon1024':      {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.falconpadded512': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.falconpadded1024':{'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincssha2128f': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincssha2128s': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincssha2192f': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincssha2192s': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincssha2256f': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincssha2256s': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincsshake128f':{'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincsshake128s':{'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincsshake192f':{'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincsshake192s':{'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincsshake256f':{'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.sphincsshake256s':{'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.hqc128':          {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.hqc192':          {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.hqc256':          {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece348864':  {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece348864f': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece460896':  {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece460896f': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece6688128': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece6688128f':{'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece6960119': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece6960119f':{'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece8192128': {'layer': 'main/keygen',         'check': 'symbol'},
    'keygen.mceliece8192128f':{'layer': 'main/keygen',         'check': 'symbol'},

    # ── primary/system_lite ───────────────────────────────────────────────────
    'lite.hash':              {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.encrypt':           {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.password':          {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.keygen':            {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.sign':              {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.pow':               {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.init':              {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.init_custom':       {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.version':           {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.variant':           {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.root_hash':         {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.root_aead':         {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.root_ecc_ed':       {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.root_ecc_x':        {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.root_pqc_kem':      {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.root_pqc_sign':     {'layer': 'primary/system_lite', 'check': 'symbol'},
    'lite.root_pow':          {'layer': 'primary/system_lite', 'check': 'symbol'},

    # ── primary/system ────────────────────────────────────────────────────────
    'system.sha256':          {'layer': 'primary/system',      'check': 'symbol'},
    'system.dhcm':            {'layer': 'primary/system',      'check': 'symbol'},
    'system.pow':             {'layer': 'primary/system',      'check': 'symbol'},
    'system.pqc_symbols':     {'layer': 'primary/system',      'check': 'symbol'},
    'system.root_hash':       {'layer': 'primary/system',      'check': 'symbol'},
    'system.root_aead':       {'layer': 'primary/system',      'check': 'symbol'},
    'system.root_ecc_ed':     {'layer': 'primary/system',      'check': 'symbol'},
    'system.root_ecc_x':      {'layer': 'primary/system',      'check': 'symbol'},
    'system.root_pqc_kem':    {'layer': 'primary/system',      'check': 'symbol'},
    'system.root_pqc_sign87': {'layer': 'primary/system',      'check': 'symbol'},

    # ── WASM  (active only when  --platform web) ───────────────────────────
    'wasm.hash_present':      {'layer': 'web/main/hash',        'check': 'file_size'},
    'wasm.core_present':      {'layer': 'web/main/core',        'check': 'file_size'},
    'wasm.pqc_present':       {'layer': 'web/main/pqc',         'check': 'file_size'},
    'wasm.pow_present':       {'layer': 'web/main/pow',         'check': 'file_size'},
    'wasm.dhcm_present':      {'layer': 'web/main/dhcm',        'check': 'file_size'},
    'wasm.main_present':      {'layer': 'web/primary/main',     'check': 'file_size'},
    'wasm.main_lite_present': {'layer': 'web/primary/main_lite','check': 'file_size'},
    'wasm.hash_kat':          {'layer': 'web/main/hash',        'check': 'wasm_module'},
    'wasm.core_kat':          {'layer': 'web/main/core',        'check': 'wasm_module'},
    'wasm.pqc_kat':           {'layer': 'web/main/pqc',         'check': 'wasm_module'},
    'wasm.pow_kat':           {'layer': 'web/main/pow',         'check': 'wasm_module'},
    'wasm.dhcm_kat':          {'layer': 'web/main/dhcm',        'check': 'wasm_module'},
    'wasm.system_kat':        {'layer': 'web/primary/main',     'check': 'wasm_module'},
    'wasm.lite_kat':          {'layer': 'web/primary/main_lite','check': 'wasm_module'},
}

# ─────────────────────────────────────────────────────────────────────────────
# Map 3 — FULL_MAP
# Complete algorithm execution.  Each algo in exactly one layer.
# ─────────────────────────────────────────────────────────────────────────────

FULL_MAP = {
    # ── main/hash ─────────────────────────────────────────────────────────────
    'hash.sha256':            {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.sha512':            {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.blake3':            {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.argon2id':          {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.argon2i':           {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.argon2d':           {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.sha3_256':          {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.sha3_512':          {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.keccak256':         {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.shake128':          {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.shake256':          {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.sha1':              {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.md5':               {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.md2':               {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},
    'hash.md4':               {'layer': 'main/hash',           'check': 'execute', 'module': 'test.main.hash'},

    # ── main/core ─────────────────────────────────────────────────────────────
    'core.aes_cbc':           {'layer': 'main/core',           'check': 'execute', 'module': 'test.main.core'},
    'core.aes_gcm':           {'layer': 'main/core',           'check': 'execute', 'module': 'test.main.core'},
    'core.chacha20':          {'layer': 'main/core',           'check': 'execute', 'module': 'test.main.core'},
    'core.ed25519':           {'layer': 'main/core',           'check': 'execute', 'module': 'test.main.core'},

    # ── main/pqc ──────────────────────────────────────────────────────────────
    'pqc.mlkem768':           {'layer': 'main/pqc',            'check': 'execute', 'module': 'test.main.pqc'},
    'pqc.mldsa44':            {'layer': 'main/pqc',            'check': 'execute', 'module': 'test.main.pqc'},

    # ── main/pow ──────────────────────────────────────────────────────────────
    'pow.sha256':             {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},
    'pow.argon2id':           {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},
    'pow.sha3':               {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},
    'pow.sha1_md5':           {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},
    'pow.md2_md4':            {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},
    'pow.dhcm_sha256':        {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},
    'pow.dhcm_argon2id':      {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},
    'pow.dhcm_sha3':          {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},
    'pow.dhcm_md5':           {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},
    'pow.dhcm_md2':           {'layer': 'main/pow',            'check': 'execute', 'module': 'test.main.pow'},

    # ── main/keygen ───────────────────────────────────────────────────────────
    'keygen.ed25519':         {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.x25519':          {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.ed448':           {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.x448':            {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.elligator2':      {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mlkem512':        {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mlkem768':        {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mlkem1024':       {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mldsa44':         {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mldsa65':         {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mldsa87':         {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.falcon512':       {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.falcon1024':      {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.falconpadded512': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.falconpadded1024':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincssha2128f': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincssha2128s': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincssha2192f': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincssha2192s': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincssha2256f': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincssha2256s': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincsshake128f':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincsshake128s':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincsshake192f':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincsshake192s':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincsshake256f':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.sphincsshake256s':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.hqc128':          {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.hqc192':          {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.hqc256':          {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece348864':  {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece348864f': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece460896':  {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece460896f': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece6688128': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece6688128f':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece6960119': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece6960119f':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece8192128': {'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},
    'keygen.mceliece8192128f':{'layer': 'main/keygen',         'check': 'execute', 'module': 'test.main.keygen'},

    # ── primary/system_lite ───────────────────────────────────────────────────
    'lite.hash':              {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.encrypt':           {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.password':          {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.keygen':            {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.sign':              {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.pow':               {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.init':              {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.init_custom':       {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.version':           {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.variant':           {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.has_algo':          {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.hash_ex':           {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.encrypt_ex':        {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.idempotent':        {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_hash':         {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_hash_rest':    {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_aead':         {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_aead_aad':     {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_ecc_ed':       {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_ecc_x':        {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_pqc_kem':      {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_pqc_sign':     {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_pow':          {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},

    # ── primary/system ────────────────────────────────────────────────────────
    'system.sha256':          {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.dhcm':            {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.pow':             {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.pqc_symbols':     {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.aes_cbc':         {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.init':            {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.encrypt':         {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.init_custom':     {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_hash':       {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_legacy':     {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_aead':       {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_ecc_ed':     {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_ecc_x':      {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_pqc_kem':    {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_pqc_sign65': {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_pqc_sign87': {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_argon2':     {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},

    # ── WASM (active only when --platform web) ────────────────────────────────
    'wasm.hash_present':      {'layer': 'web/main/hash',        'check': 'file_size', 'module': None},
    'wasm.core_present':      {'layer': 'web/main/core',        'check': 'file_size', 'module': None},
    'wasm.pqc_present':       {'layer': 'web/main/pqc',         'check': 'file_size', 'module': None},
    'wasm.pow_present':       {'layer': 'web/main/pow',         'check': 'file_size', 'module': None},
    'wasm.dhcm_present':      {'layer': 'web/main/dhcm',        'check': 'file_size', 'module': None},
    'wasm.main_present':      {'layer': 'web/primary/main',     'check': 'file_size', 'module': None},
    'wasm.main_lite_present': {'layer': 'web/primary/main_lite','check': 'file_size', 'module': None},
    'wasm.hash_selftest':     {'layer': 'web/main/hash',        'check': 'wasm_exec', 'module': None},
    'wasm.core_selftest':     {'layer': 'web/main/core',        'check': 'wasm_exec', 'module': None},
    'wasm.pqc_selftest':      {'layer': 'web/main/pqc',         'check': 'wasm_exec', 'module': None},
    'wasm.pow_selftest':      {'layer': 'web/main/pow',         'check': 'wasm_exec', 'module': None},
    'wasm.dhcm_selftest':     {'layer': 'web/main/dhcm',        'check': 'wasm_exec', 'module': None},
    'wasm.main_selftest':     {'layer': 'web/primary/main',     'check': 'wasm_exec', 'module': None},
    'wasm.main_lite_selftest':{'layer': 'web/primary/main_lite','check': 'wasm_exec', 'module': None},
    'wasm.hash_kat':          {'layer': 'web/main/hash',        'check': 'wasm_module', 'module': None},
    'wasm.core_kat':          {'layer': 'web/main/core',        'check': 'wasm_module', 'module': None},
    'wasm.pqc_kat':           {'layer': 'web/main/pqc',         'check': 'wasm_module', 'module': None},
    'wasm.pow_kat':           {'layer': 'web/main/pow',         'check': 'wasm_module', 'module': None},
    'wasm.dhcm_kat':          {'layer': 'web/main/dhcm',        'check': 'wasm_module', 'module': None},
    'wasm.system_kat':        {'layer': 'web/primary/main',     'check': 'wasm_module', 'module': None},
    'wasm.lite_kat':          {'layer': 'web/primary/main_lite','check': 'wasm_module', 'module': None},
}

# ─────────────────────────────────────────────────────────────────────────────
# Map 4 — HYPER_EXTRAS + HYPER_MAP
# FULL_MAP + cross-layer duplicates for exhaustive coverage.
# ─────────────────────────────────────────────────────────────────────────────

HYPER_EXTRAS = {
    # Hash algos re-tested through primary dispatch
    'system.sha256':          {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'lite.hash':              {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},

    # Cipher / ECC re-tested through primary high-level API
    'system.aes_cbc':         {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_ecc_ed':     {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_ecc_x':      {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},

    # PQC re-tested at higher parameter set in primary
    'system.root_pqc_kem':    {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'system.root_pqc_sign87': {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'lite.root_pqc_kem':      {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},
    'lite.root_pqc_sign':     {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},

    # PoW re-tested at root API level in primary
    'system.pow':             {'layer': 'primary/system',      'check': 'execute', 'module': 'test.primary.system'},
    'lite.root_pow':          {'layer': 'primary/system_lite', 'check': 'execute', 'module': 'test.primary.system_lite'},

    # WASM selftests added on top of file-size checks
    'wasm.hash_selftest':     {'layer': 'web/main/hash',        'check': 'wasm_exec', 'module': None},
    'wasm.core_selftest':     {'layer': 'web/main/core',        'check': 'wasm_exec', 'module': None},
    'wasm.pqc_selftest':      {'layer': 'web/main/pqc',         'check': 'wasm_exec', 'module': None},
    'wasm.pow_selftest':      {'layer': 'web/main/pow',         'check': 'wasm_exec', 'module': None},
    'wasm.main_selftest':     {'layer': 'web/primary/main',     'check': 'wasm_exec', 'module': None},
    'wasm.main_lite_selftest':{'layer': 'web/primary/main_lite','check': 'wasm_exec', 'module': None},
    # WASM Python/wasmtime KATs added on top of selftests
    'wasm.hash_kat':          {'layer': 'web/main/hash',        'check': 'wasm_module', 'module': None},
    'wasm.core_kat':          {'layer': 'web/main/core',        'check': 'wasm_module', 'module': None},
    'wasm.pqc_kat':           {'layer': 'web/main/pqc',         'check': 'wasm_module', 'module': None},
    'wasm.pow_kat':           {'layer': 'web/main/pow',         'check': 'wasm_module', 'module': None},
    'wasm.dhcm_kat':          {'layer': 'web/main/dhcm',        'check': 'wasm_module', 'module': None},
    'wasm.system_kat':        {'layer': 'web/primary/main',     'check': 'wasm_module', 'module': None},
    'wasm.lite_kat':          {'layer': 'web/primary/main_lite','check': 'wasm_module', 'module': None},
}

HYPER_MAP = {**FULL_MAP, **HYPER_EXTRAS}
