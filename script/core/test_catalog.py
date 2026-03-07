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
}

HYPER_MAP = {**FULL_MAP, **HYPER_EXTRAS}
