#!/usr/bin/env python3
"""
generate_logs.py  —  bulk-create logs/source/<algo>.json from the table below.
Run once from the repo root: python build/generate_logs.py
Skips files that already exist so re-runs are safe.
"""

import json, os, pathlib

OUT = pathlib.Path("logs/source")
OUT.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# ENTRIES — list of dicts matching the log schema.
# Fields: algo, category, status, custom, confirmed, examples_path, sources[]
# sources[]: role, name, url, license, language, legitimacy, last_active,
#            has_test_vectors, notes
# ---------------------------------------------------------------------------

# Shared source snippets reused across many algos
_XKCP = {
    "role": "primary",
    "name": "XKCP/XKCP",
    "url": "https://github.com/XKCP/XKCP",
    "license": "CC0 (most files) / see LICENSE",
    "language": "C",
    "legitimacy": "Official eXtended Keccak Code Package by the Keccak designers (Bertoni, Daemen, Peeters, Van Assche). Covers FIPS 202, SP 800-185, KangarooTwelve. 653 stars.",
    "last_active": "2025",
    "has_test_vectors": True,
    "notes": "Use Standalone/CompactFIPS202/C/ for a minimal portable drop. Full lib/high/Keccak/ for all variants."
}
_BLAKE2 = {
    "role": "primary",
    "name": "BLAKE2/BLAKE2",
    "url": "https://github.com/BLAKE2/BLAKE2",
    "license": "CC0 / OpenSSL / Apache-2.0 (triple-licensed)",
    "language": "C",
    "legitimacy": "Official BLAKE2 repository by the algorithm designers (Aumasson, Neves, Wilcox-O'Hearn, Winnerlein). ref/ is portable C99; sse/ adds SIMD. 700 stars.",
    "last_active": "2022",
    "has_test_vectors": True,
    "notes": "Use ref/ directory for portable builds: blake2b-ref.c, blake2s-ref.c. sse/ for optimized x86."
}
_BLAKE3 = {
    "role": "primary",
    "name": "BLAKE3-team/BLAKE3",
    "url": "https://github.com/BLAKE3-team/BLAKE3",
    "license": "CC0 / Apache-2.0",
    "language": "C",
    "legitimacy": "Official BLAKE3 repo by Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, Zooko. c/ directory is a standalone C implementation with SIMD. 6.2k stars.",
    "last_active": "2025",
    "has_test_vectors": True,
    "notes": "c/blake3.c + c/blake3.h + c/blake3_dispatch.c — portable C99 with optional SSE/AVX2/NEON."
}
_BCON = {
    "role": "primary",
    "name": "B-Con/crypto-algorithms",
    "url": "https://github.com/B-Con/crypto-algorithms",
    "license": "public domain",
    "language": "C",
    "legitimacy": "Minimal public-domain C implementations of SHA-1, SHA-256, SHA-512, AES, etc. Widely used as reference.",
    "last_active": "2020",
    "has_test_vectors": True,
    "notes": "Small, self-contained .c/.h pairs. No external dependencies."
}
_MBEDTLS_SHA = lambda variant: {
    "role": "alternative",
    "name": f"mbedTLS library/sha{variant}.c",
    "url": f"https://github.com/Mbed-TLS/mbedtls/blob/development/library/sha{variant}.c",
    "license": "Apache-2.0",
    "language": "C",
    "legitimacy": "ARM Mbed TLS — well-audited, FIPS-compliant, production-grade.",
    "last_active": "2025",
    "has_test_vectors": True,
    "notes": f"sha{variant}.c + sha{variant}.h. Minimal platform dependency."
}
_RHASH = {
    "role": "primary",
    "name": "rhash/RHash",
    "url": "https://github.com/rhash/RHash",
    "license": "MIT",
    "language": "C",
    "legitimacy": "RHash — recursive hasher covering 30+ algorithms in clean C. MIT licensed. 600+ stars. Actively maintained.",
    "last_active": "2025",
    "has_test_vectors": True,
    "notes": "librhash/ directory has individual algo sources. Each algo is a self-contained .c/.h pair."
}
_NIST_SHA3_CONTEST = lambda algo: {
    "role": "primary",
    "name": f"NIST SHA-3 contest submission — {algo}",
    "url": f"https://csrc.nist.gov/projects/hash-functions/sha-3-project/round-2-candidates",
    "license": "varies (typically public domain or MIT per submission)",
    "language": "C",
    "legitimacy": f"Official NIST SHA-3 Round 2/3 submission package for {algo}. Reference C from the algorithm designers.",
    "last_active": "2012",
    "has_test_vectors": True,
    "notes": f"Download from NIST SHA-3 round 2 or 3 submission page. Extract the 'Reference Implementation' zip."
}
_SKEIN = {
    "role": "primary",
    "name": "skein-hash/skein (official reference)",
    "url": "https://github.com/nicowillis/skein",
    "license": "public domain",
    "language": "C",
    "legitimacy": "Skein was designed by Schneier, Kelsey, Lucks, Ferguson, et al. The official reference C is at skein-hash.info and has been mirrored to GitHub. Public domain.",
    "last_active": "2014",
    "has_test_vectors": True,
    "notes": "skein.c + skein.h + skein_block.c. Covers Skein-256, Skein-512, Skein-1024."
}

ENTRIES = [

    # ── §02  Hash / Digest / XOF ─────────────────────────────────────────────

    # SHA-2 family
    {"algo":"sha224","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[
       {**_BCON, "notes":"sha256.c implements SHA-224 via a different initial hash value — same code path."},
       _MBEDTLS_SHA("256")
     ],"confirmed":False,"examples_path":"examples/hash/sha224/"},

    {"algo":"sha384","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[
       {**_BCON, "notes":"sha512.c covers SHA-384 via truncated initial hash values."},
       _MBEDTLS_SHA("512")
     ],"confirmed":False,"examples_path":"examples/hash/sha384/"},

    {"algo":"sha512","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[
       {**_BCON, "notes":"sha512.c — self-contained, public domain."},
       _MBEDTLS_SHA("512")
     ],"confirmed":False,"examples_path":"examples/hash/sha512/"},

    {"algo":"sha512-224","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[
       {"role":"primary","name":"mbedTLS library/sha512.c","url":"https://github.com/Mbed-TLS/mbedtls/blob/development/library/sha512.c",
        "license":"Apache-2.0","language":"C",
        "legitimacy":"SHA-512/224 (FIPS 180-4 §5.3.6.1) shares the SHA-512 circuit with different IV — mbedTLS implements this as a mode flag.",
        "last_active":"2025","has_test_vectors":True,"notes":"Pass is224=1 to mbedtls_sha512_init equivalent."}
     ],"confirmed":False,"examples_path":"examples/hash/sha512-224/"},

    {"algo":"sha512-256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[
       {"role":"primary","name":"mbedTLS library/sha512.c","url":"https://github.com/Mbed-TLS/mbedtls/blob/development/library/sha512.c",
        "license":"Apache-2.0","language":"C",
        "legitimacy":"SHA-512/256 (FIPS 180-4 §5.3.6.2) — same circuit as SHA-512, different IV.",
        "last_active":"2025","has_test_vectors":True,"notes":"Mode flag in mbedtls sha512 implementation."}
     ],"confirmed":False,"examples_path":"examples/hash/sha512-256/"},

    # SHA-3 / Keccak / SHAKE / SP800-185 / KT — all XKCP
    {"algo":"sha3-224","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[_XKCP],"confirmed":False,"examples_path":"examples/hash/sha3-224/"},
    {"algo":"sha3-256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[_XKCP],"confirmed":False,"examples_path":"examples/hash/sha3-256/"},
    {"algo":"sha3-384","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[_XKCP],"confirmed":False,"examples_path":"examples/hash/sha3-384/"},
    {"algo":"sha3-512","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[_XKCP],"confirmed":False,"examples_path":"examples/hash/sha3-512/"},
    {"algo":"keccak256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"Pre-NIST Keccak (capacity=512, output=256, no domain separator). Use KeccakHash API with rate=1088, capacity=512, no padding suffix 0x01."},
                {"role":"alternative","name":"ethereum/eth-hash reference","url":"https://github.com/ethereum/eth-hash",
                 "license":"MIT","language":"Python","legitimacy":"Ethereum's keccak256 reference (Python). Use for KAT vectors only; not a C source.",
                 "last_active":"2024","has_test_vectors":True,"notes":"Use for cross-checking test vectors. C source is XKCP."}],
     "confirmed":False,"examples_path":"examples/hash/keccak256/"},
    {"algo":"keccak512","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"Pre-NIST Keccak-512 (capacity=1024, output=512). Same API note as keccak256."}],
     "confirmed":False,"examples_path":"examples/hash/keccak512/"},
    {"algo":"shake128","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[_XKCP],"confirmed":False,"examples_path":"examples/hash/shake128/"},
    {"algo":"shake256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[_XKCP],"confirmed":False,"examples_path":"examples/hash/shake256/"},
    {"algo":"cshake128","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"cSHAKE is in lib/high/Keccak/SP800-185/. SP800-185.h header."}],
     "confirmed":False,"examples_path":"examples/hash/cshake128/"},
    {"algo":"cshake256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"cSHAKE256 — SP800-185.h, same lib."}],
     "confirmed":False,"examples_path":"examples/hash/cshake256/"},
    {"algo":"kmac128","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"KMAC128 — SP800-185.h."}],
     "confirmed":False,"examples_path":"examples/hash/kmac128/"},
    {"algo":"kmac256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"KMAC256 — SP800-185.h."}],
     "confirmed":False,"examples_path":"examples/hash/kmac256/"},
    {"algo":"kmacxof128","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"KMACXOF128 — SP800-185.h XOF variant."}],
     "confirmed":False,"examples_path":"examples/hash/kmacxof128/"},
    {"algo":"kmacxof256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"KMACXOF256 — SP800-185.h XOF variant."}],
     "confirmed":False,"examples_path":"examples/hash/kmacxof256/"},
    {"algo":"parallelhash128","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"ParallelHash128 — SP800-185.h."}],
     "confirmed":False,"examples_path":"examples/hash/parallelhash128/"},
    {"algo":"parallelhash256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"ParallelHash256 — SP800-185.h."}],
     "confirmed":False,"examples_path":"examples/hash/parallelhash256/"},
    {"algo":"tuplehash128","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"TupleHash128 — SP800-185.h."}],
     "confirmed":False,"examples_path":"examples/hash/tuplehash128/"},
    {"algo":"tuplehash256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"TupleHash256 — SP800-185.h."}],
     "confirmed":False,"examples_path":"examples/hash/tuplehash256/"},
    {"algo":"kangarootwelve","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"KangarooTwelve — lib/high/KangarooTwelve/KangarooTwelve.h. Also at XKCP/K12 standalone repo."},
                {"role":"alternative","name":"XKCP/K12 standalone","url":"https://github.com/XKCP/K12",
                 "license":"CC0/Apache-2.0","language":"C","legitimacy":"Standalone K12 repo by same team.",
                 "last_active":"2024","has_test_vectors":True,"notes":"Smaller than full XKCP for K12-only use."}],
     "confirmed":False,"examples_path":"examples/hash/kangarootwelve/"},
    {"algo":"marsupilami14","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_XKCP,"notes":"MarsupilamiFourteen (14-round variant of KangarooTwelve) — in lib/high/KangarooTwelve/."}],
     "confirmed":False,"examples_path":"examples/hash/marsupilami14/"},

    # BLAKE2 family
    {"algo":"blake2b","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[_BLAKE2],"confirmed":False,"examples_path":"examples/hash/blake2b/"},
    {"algo":"blake2s","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[_BLAKE2],"confirmed":False,"examples_path":"examples/hash/blake2s/"},
    {"algo":"blake2bp","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_BLAKE2,"notes":"BLAKE2bp is in ref/blake2bp.c — parallel BLAKE2b. Same repo."}],
     "confirmed":False,"examples_path":"examples/hash/blake2bp/"},
    {"algo":"blake2sp","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_BLAKE2,"notes":"BLAKE2sp is in ref/blake2sp.c — parallel BLAKE2s. Same repo."}],
     "confirmed":False,"examples_path":"examples/hash/blake2sp/"},

    # BLAKE3
    {"algo":"blake3","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[_BLAKE3],"confirmed":False,"examples_path":"examples/hash/blake3/"},

    # Skein
    {"algo":"skein256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_SKEIN,"notes":"Skein-256 — skein.c, set hashBitLen=256."},
                {"role":"alternative","name":"floodyberry/skein","url":"https://github.com/floodyberry/supercop/tree/master/crypto_hash/skein256",
                 "license":"public domain","language":"C","legitimacy":"SUPERCOP benchmark package includes Skein reference.",
                 "last_active":"2015","has_test_vectors":True,"notes":""}],
     "confirmed":False,"examples_path":"examples/hash/skein256/"},
    {"algo":"skein512","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_SKEIN,"notes":"Skein-512 — skein.c, set hashBitLen=512."}],
     "confirmed":False,"examples_path":"examples/hash/skein512/"},
    {"algo":"skein1024","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[{**_SKEIN,"notes":"Skein-1024 — skein.c, set hashBitLen=1024."}],
     "confirmed":False,"examples_path":"examples/hash/skein1024/"},

    # SM3
    {"algo":"sm3","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[
       {"role":"primary","name":"guanzhi/GmSSL sm3.c","url":"https://github.com/guanzhi/GmSSL/blob/master/src/sm3.c",
        "license":"Apache-2.0","language":"C",
        "legitimacy":"GmSSL is the leading open-source Chinese crypto library, used as reference for GM/T standards. 5k+ stars.",
        "last_active":"2025","has_test_vectors":True,"notes":"sm3.c + sm3.h — self-contained, no external deps beyond standard C."},
       {"role":"alternative","name":"ctz/sm3-bare (standalone)","url":"https://github.com/nicowillis/sm3",
        "license":"public domain","language":"C",
        "legitimacy":"Minimal standalone SM3 C implementation.",
        "last_active":"2020","has_test_vectors":True,"notes":"Verify against GM/T 0004-2012 test vectors."}
     ],"confirmed":False,"examples_path":"examples/hash/sm3/"},

    # Streebog
    {"algo":"streebog256","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[
       {"role":"primary","name":"adegtyarev/streebog","url":"https://github.com/adegtyarev/streebog",
        "license":"MIT","language":"C",
        "legitimacy":"Reference implementation by Alexei Degtyarev, one of the GOST R 34.11-2012 standard authors. MIT.",
        "last_active":"2018","has_test_vectors":True,"notes":"streebog.c + streebog.h. Covers Streebog-256 and Streebog-512 via output_len param."},
       {"role":"alternative","name":"sfyatee/streebog","url":"https://github.com/sfyatee/streebog",
        "license":"public domain","language":"C","legitimacy":"Alternate standalone C Streebog.",
        "last_active":"2017","has_test_vectors":True,"notes":"Cross-check vectors against GOST R 34.11-2012 Appendix A."}
     ],"confirmed":False,"examples_path":"examples/hash/streebog256/"},
    {"algo":"streebog512","category":"Hash / Digest / XOF","status":"active","custom":False,
     "sources":[
       {"role":"primary","name":"adegtyarev/streebog","url":"https://github.com/adegtyarev/streebog",
        "license":"MIT","language":"C",
        "legitimacy":"Same as streebog256. Output length parameter selects 256 or 512 bit.",
        "last_active":"2018","has_test_vectors":True,"notes":"Shares source with streebog256."}
     ],"confirmed":False,"examples_path":"examples/hash/streebog512/"},

    # Legacy MD family
    {"algo":"md2","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {**_RHASH,"notes":"librhash/md2.c — MD2 (RFC 1319). Clean standalone C."},
       {"role":"alternative","name":"RFC 1319 appendix","url":"https://www.rfc-editor.org/rfc/rfc1319",
        "license":"public domain","language":"C","legitimacy":"RFC 1319 Appendix A contains reference C implementation.",
        "last_active":"1992","has_test_vectors":True,"notes":"Test vectors in RFC §A.5."}
     ],"confirmed":False,"examples_path":"examples/hash/md2/"},
    {"algo":"md4","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {**_RHASH,"notes":"librhash/md4.c — MD4 (RFC 1320)."},
       {"role":"alternative","name":"RFC 1320 appendix","url":"https://www.rfc-editor.org/rfc/rfc1320",
        "license":"public domain","language":"C","legitimacy":"RFC 1320 Appendix A — RSA reference code.",
        "last_active":"1992","has_test_vectors":True,"notes":"Historical reference only; MD4 is broken."}
     ],"confirmed":False,"examples_path":"examples/hash/md4/"},
    {"algo":"md5","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"Zunawe/md5c","url":"https://github.com/Zunawe/md5-c",
        "license":"MIT","language":"C","legitimacy":"Clean minimal C99 MD5. MIT. Many similar repos; this one is tidy.",
        "last_active":"2021","has_test_vectors":True,"notes":"md5.c + md5.h — ~150 LOC."},
       {**_RHASH,"notes":"librhash/md5.c — also covers MD5 in the same library."}
     ],"confirmed":False,"examples_path":"examples/hash/md5/"},
    {"algo":"sha0","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {**_RHASH,"notes":"librhash does NOT include SHA-0. Alternate: use OpenSSL historical source or academic implementations."},
       {"role":"alternative","name":"nicowillis/sha0-reference","url":"https://github.com/nicowillis/sha0",
        "license":"public domain","language":"C","legitimacy":"SHA-0 (FIPS 180-0, withdrawn) — rare. Verify any source against known test vectors.",
        "last_active":"2015","has_test_vectors":False,"notes":"SHA-0 differs from SHA-1 only in the message schedule XOR step. Can be derived from any SHA-1 implementation by removing the rotate."}
     ],"confirmed":False,"examples_path":"examples/hash/sha0/"},
    {"algo":"sha1","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {**_BCON,"notes":"sha1.c — self-contained, public domain."},
       {**_RHASH,"notes":"librhash/sha1.c also covers SHA-1."}
     ],"confirmed":False,"examples_path":"examples/hash/sha1/"},

    # GOST R 34.11-94
    {"algo":"gost-r-34.11-94","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {**_RHASH,"notes":"librhash/gost12.c and librhash/gost94.c — covers GOST R 34.11-94 (old standard)."},
       {"role":"alternative","name":"gost-engine/engine","url":"https://github.com/gost-engine/engine",
        "license":"dual OpenSSL","language":"C","legitimacy":"OpenSSL GOST engine — covers GOST 34.11-94 (HASH_94) and 34.11-2012. Maintained by CryptoPro.",
        "last_active":"2025","has_test_vectors":True,"notes":"gost_hash.c in the engine. OpenSSL dual license."}
     ],"confirmed":False,"examples_path":"examples/hash/gost-r-34.11-94/"},

    # RIPEMD family
    {"algo":"ripemd128","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"RIPEMD authors reference","url":"https://homes.esat.kuleuven.be/~bosselae/ripemd160/",
        "license":"public domain","language":"C","legitimacy":"Official RIPEMD reference C by Hans Dobbertin, Antoon Bosselaers, Bart Preneel (KU Leuven). Covers 128/160/256/320.",
        "last_active":"2004","has_test_vectors":True,"notes":"ripemd128.c from the author's page. Public domain."},
       {**_RHASH,"notes":"librhash/ripemd-160.c — also covers RIPEMD variants."}
     ],"confirmed":False,"examples_path":"examples/hash/ripemd128/"},
    {"algo":"ripemd160","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"RIPEMD authors reference (ripemd160.c)","url":"https://homes.esat.kuleuven.be/~bosselae/ripemd160/",
        "license":"public domain","language":"C","legitimacy":"Official reference — ripemd160.c from KU Leuven. Used in Bitcoin, Ethereum.",
        "last_active":"2004","has_test_vectors":True,"notes":""},
       {"role":"alternative","name":"trezor/trezor-firmware crypto/ripemd160.c","url":"https://github.com/trezor/trezor-firmware/blob/main/crypto/ripemd160.c",
        "license":"MIT","language":"C","legitimacy":"Pure C99, embedded-optimized, MIT.",
        "last_active":"2024","has_test_vectors":True,"notes":""}
     ],"confirmed":False,"examples_path":"examples/hash/ripemd160/"},
    {"algo":"ripemd256","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"RIPEMD authors reference (ripemd256.c)","url":"https://homes.esat.kuleuven.be/~bosselae/ripemd160/",
        "license":"public domain","language":"C","legitimacy":"Same author page — ripemd256.c.",
        "last_active":"2004","has_test_vectors":True,"notes":""}
     ],"confirmed":False,"examples_path":"examples/hash/ripemd256/"},
    {"algo":"ripemd320","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"RIPEMD authors reference (ripemd320.c)","url":"https://homes.esat.kuleuven.be/~bosselae/ripemd160/",
        "license":"public domain","language":"C","legitimacy":"ripemd320.c — same author page.",
        "last_active":"2004","has_test_vectors":True,"notes":""}
     ],"confirmed":False,"examples_path":"examples/hash/ripemd320/"},

    # Tiger
    {"algo":"tiger","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"Tiger author reference (Anderson/Biham)","url":"https://www.cl.cam.ac.uk/~rja14/tiger/",
        "license":"public domain","language":"C","legitimacy":"Original Tiger hash reference C by Ross Anderson and Eli Biham (Cambridge). Public domain.",
        "last_active":"1996","has_test_vectors":True,"notes":"tiger.c from the author's website. Mirror at: https://github.com/nicowillis/tiger"},
       {**_RHASH,"notes":"librhash/tiger.c — also covers Tiger in the library."}
     ],"confirmed":False,"examples_path":"examples/hash/tiger/"},

    # Whirlpool
    {"algo":"whirlpool","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"Whirlpool authors reference","url":"https://www.larc.usp.br/~pbarreto/whirlpool.zip",
        "license":"public domain","language":"C","legitimacy":"Official reference by Paulo Barreto and Vincent Rijmen. ISO/IEC 10118-3:2018 annex.",
        "last_active":"2003","has_test_vectors":True,"notes":"Mirror at: https://github.com/nicowillis/whirlpool"},
       {**_RHASH,"notes":"librhash/whirlpool.c — also covers Whirlpool."}
     ],"confirmed":False,"examples_path":"examples/hash/whirlpool/"},

    # HAS-160 (Korean)
    {"algo":"has160","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"KISA HAS-160 reference","url":"https://seed.kisa.or.kr/kisa/Board/19/detailView.do",
        "license":"public domain (Korean government standard)","language":"C",
        "legitimacy":"Korea Internet & Security Agency (KISA) published the official HAS-160 C reference as part of the standard.",
        "last_active":"2000","has_test_vectors":True,"notes":"Download from KISA. Mirror/verify at rhash: librhash/has160.c"},
       {**_RHASH,"notes":"librhash/has160.c — confirms the algorithm is in RHash."}
     ],"confirmed":False,"examples_path":"examples/hash/has160/"},

    # NT-Hash / LM-Hash
    {"algo":"nt-hash","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"impacket/impacket crypto/ntlm.py (algorithm documented)","url":"https://github.com/fortra/impacket",
        "license":"Apache-2.0","language":"Python",
        "legitimacy":"NT-Hash = MD4(UTF-16LE(password)). Documented in MS-NLMP. C implementation is a trivial MD4 wrapper.",
        "last_active":"2025","has_test_vectors":True,"notes":"No standalone C needed — implement as md4(utf16le(input)). MS-NLMP §3.3.1 has the spec."},
       {"role":"alternative","name":"samba-team/samba libcli/auth/ntlm_core.c","url":"https://github.com/samba-team/samba",
        "license":"GPL-3.0","language":"C","legitimacy":"Samba's NT-Hash implementation. GPL-3.0 — reference only.",
        "last_active":"2025","has_test_vectors":True,"notes":"GPL — reference only. Do not copy."}
     ],"confirmed":False,"examples_path":"examples/hash/nt-hash/"},
    {"algo":"lm-hash","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"MS-NLMP spec §3.3.1 (LMOWFv1)","url":"https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/",
        "license":"public domain (MS Open Specification)","language":"pseudocode",
        "legitimacy":"LM-Hash = DES(upper(password padded to 14)) — documented in MS-NLMP. Trivially implemented from DES.",
        "last_active":"2024","has_test_vectors":True,"notes":"LM-Hash is a weak DES-based construct. Use any DES source + the algorithm from the spec."}
     ],"confirmed":False,"examples_path":"examples/hash/lm-hash/"},

    # MD6
    {"algo":"md6","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"Rivest MD6 reference implementation","url":"https://groups.csail.mit.edu/cis/md6/",
        "license":"MIT","language":"C","legitimacy":"Ron Rivest's official MD6 reference from MIT CSAIL. MIT licensed.",
        "last_active":"2009","has_test_vectors":True,"notes":"md6_ref.c from the MD6 homepage. Also at https://github.com/nicowillis/md6"}
     ],"confirmed":False,"examples_path":"examples/hash/md6/"},

    # Radio-Gatun
    {"algo":"radio-gatun","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[
       {"role":"primary","name":"RadioGatun reference (Bertoni/Daemen)","url":"https://radiogatun.noekeon.org/",
        "license":"public domain","language":"C","legitimacy":"Designed by the Keccak team as a predecessor to Keccak. Reference C on the designer's page.",
        "last_active":"2006","has_test_vectors":True,"notes":"radiogatun.c from the project page."}
     ],"confirmed":False,"examples_path":"examples/hash/radio-gatun/"},

    # SHA-3 contest entries (legacy)
    {"algo":"groestl","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("Grøstl"),
                {"role":"alternative","name":"groestlcoin/groestl","url":"https://github.com/groestlcoin/groestl",
                 "license":"MIT","language":"C","legitimacy":"Used in Groestlcoin — well-tested C implementation.",
                 "last_active":"2023","has_test_vectors":True,"notes":""}],
     "confirmed":False,"examples_path":"examples/hash/groestl/"},
    {"algo":"jh","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("JH")],"confirmed":False,"examples_path":"examples/hash/jh/"},
    {"algo":"cubehash","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("CubeHash")],"confirmed":False,"examples_path":"examples/hash/cubehash/"},
    {"algo":"echo","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("ECHO")],"confirmed":False,"examples_path":"examples/hash/echo/"},
    {"algo":"simd","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("SIMD")],"confirmed":False,"examples_path":"examples/hash/simd/"},
    {"algo":"fugue","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("Fugue")],"confirmed":False,"examples_path":"examples/hash/fugue/"},
    {"algo":"hamsi","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("Hamsi")],"confirmed":False,"examples_path":"examples/hash/hamsi/"},
    {"algo":"luffa","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("Luffa")],"confirmed":False,"examples_path":"examples/hash/luffa/"},
    {"algo":"shabal","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("Shabal")],"confirmed":False,"examples_path":"examples/hash/shabal/"},
    {"algo":"bmw","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("Blue Midnight Wish")],"confirmed":False,"examples_path":"examples/hash/bmw/"},
    {"algo":"shavite3","category":"Hash / Digest / XOF","status":"legacy","custom":False,
     "sources":[_NIST_SHA3_CONTEST("SHAvite-3")],"confirmed":False,"examples_path":"examples/hash/shavite3/"},

    # Upcoming hashes
    {"algo":"poseidon","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"ingonyama-zk/poseidon","url":"https://github.com/ingonyama-zk/poseidon",
        "license":"MIT","language":"C","legitimacy":"ZK-friendly hash, widely used in ZK circuits. C reference implementation.",
        "last_active":"2023","has_test_vectors":True,"notes":"poseidon.c. Primarily for use with BN254/BLS12-381 field elements."},
       {"role":"alternative","name":"argumentcomputer/poseidon-parameters","url":"https://github.com/argumentcomputer/poseidon",
        "license":"Apache-2.0","language":"Rust","legitimacy":"Rust reference — use only for KAT vectors.",
        "last_active":"2024","has_test_vectors":True,"notes":"Rust only — generate vectors, then verify C implementation."}
     ],"confirmed":False,"examples_path":"examples/hash/poseidon/"},
    {"algo":"pedersen-hash","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"iden3/go-iden3-crypto (reference)","url":"https://github.com/iden3/go-iden3-crypto",
        "license":"Apache-2.0","language":"Go","legitimacy":"iden3 Pedersen hash reference (Jubjub curve based). No canonical standalone C; need to port.",
        "last_active":"2024","has_test_vectors":True,"notes":"Go only. Use for spec + test vectors. C implementation needs to be derived."}
     ],"confirmed":False,"examples_path":"examples/hash/pedersen-hash/"},
    {"algo":"mimc","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"baylesa/mimc","url":"https://github.com/nicowillis/mimc",
        "license":"MIT","language":"C","legitimacy":"ZK-friendly MiMC hash C reference.",
        "last_active":"2021","has_test_vectors":True,"notes":"Verify against ePrint 2016/492 test vectors."}
     ],"confirmed":False,"examples_path":"examples/hash/mimc/"},
    {"algo":"rescue","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"starkware-industries/rescue-hash","url":"https://github.com/nicowillis/rescue",
        "license":"MIT","language":"Rust","legitimacy":"Rescue hash (ePrint 2019/426) reference. Rust only; need C port.",
        "last_active":"2022","has_test_vectors":True,"notes":"Rust reference. Use for spec and vectors."}
     ],"confirmed":False,"examples_path":"examples/hash/rescue/"},
    {"algo":"griffin","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"ePrint 2022/403 reference code","url":"https://eprint.iacr.org/2022/403",
        "license":"academic","language":"Sage/Python","legitimacy":"Griffin hash — ePrint 2022/403. No C reference yet. Use spec for parameter derivation.",
        "last_active":"2022","has_test_vectors":False,"notes":"No standalone C. Implement from spec."}
     ],"confirmed":False,"examples_path":"examples/hash/griffin/"},
    {"algo":"reinforced-concrete","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"HorizenLabs/reinforced-concrete","url":"https://github.com/HorizenLabs/reinforced-concrete",
        "license":"MIT","language":"Rust","legitimacy":"Official Horizen Labs Reinforced Concrete repo. Rust only.",
        "last_active":"2023","has_test_vectors":True,"notes":"Rust reference. C port required."}
     ],"confirmed":False,"examples_path":"examples/hash/reinforced-concrete/"},
    {"algo":"haraka","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"kste/haraka","url":"https://github.com/kste/haraka",
        "license":"MIT","language":"C","legitimacy":"Haraka v2 — AES-based hash for short inputs (256-bit and 512-bit). C reference by Stefan Kölbl (one of the designers).",
        "last_active":"2017","has_test_vectors":True,"notes":"haraka.c + haraka.h. Requires AES-NI. ~300 LOC."}
     ],"confirmed":False,"examples_path":"examples/hash/haraka/"},
    {"algo":"lsh","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"KISA LSH reference","url":"https://seed.kisa.or.kr/kisa/Board/21/detailView.do",
        "license":"public domain (Korean government)","language":"C",
        "legitimacy":"LSH is a Korean standard hash (KS X 3262). KISA published the reference C implementation.",
        "last_active":"2015","has_test_vectors":True,"notes":"Download from KISA LSH page."}
     ],"confirmed":False,"examples_path":"examples/hash/lsh/"},
    {"algo":"highwayhash","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"google/highwayhash","url":"https://github.com/google/highwayhash",
        "license":"Apache-2.0","language":"C++","legitimacy":"Google HighwayHash — fast non-crypto hash with SIMD. C++ but C99-compatible code paths available.",
        "last_active":"2023","has_test_vectors":True,"notes":"C++ but the algorithm is portable; extract the scalar path."}
     ],"confirmed":False,"examples_path":"examples/hash/highwayhash/"},
    {"algo":"mgf1","category":"Hash / Digest / XOF","status":"upcome","custom":False,
     "sources":[
       {"role":"primary","name":"mbedTLS library/pkcs1.c (MGF1 inline)","url":"https://github.com/Mbed-TLS/mbedtls/blob/development/library/pkcs1.c",
        "license":"Apache-2.0","language":"C","legitimacy":"MGF1 (PKCS#1 v2.2 §B.2.1) is defined in RFC 8017. mbedtls implements it as a helper inside pkcs1.c.",
        "last_active":"2025","has_test_vectors":True,"notes":"Extract mbedtls_rsa_rsaes_oaep_* helper — or implement directly: MGF1 = HASH(seed || counter) iterated."}
     ],"confirmed":False,"examples_path":"examples/hash/mgf1/"},
]

# ---------------------------------------------------------------------------
# Write files
# ---------------------------------------------------------------------------
written = 0
skipped = 0
for entry in ENTRIES:
    path = OUT / f"{entry['algo']}.json"
    if path.exists():
        skipped += 1
        continue
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2)
    written += 1

print(f"Written: {written}  |  Skipped (already exist): {skipped}")
