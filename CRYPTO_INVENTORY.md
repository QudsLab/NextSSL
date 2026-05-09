# Comprehensive Cryptographic Algorithm & Library Inventory
> SQL-normalized schema and flat-hash layout hybrid. Status: `current` = in-production surface; `planned` = roadmap surface; `legacy` = deprecated but inventoried; `historic` = academically/historically significant.

---

## Schema Definition (SQL-style)

### Table: `algorithm`
```sql
CREATE TABLE algorithm (
    algo_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    algo_name           TEXT    NOT NULL UNIQUE,          -- canonical surface name
    algo_alias          TEXT,                             -- comma-separated aliases
    category_fk         INTEGER NOT NULL REFERENCES category(cat_id),
    status              TEXT    NOT NULL CHECK(status IN ('current','planned','legacy','historic')),
    type                TEXT    NOT NULL,                  -- functional type tag
    security_level      TEXT,                             -- bits of security or NIST level
    standard            TEXT,                             -- governing RFC/FIPS/ISO/SP
    note                TEXT,
    streaming_capable   BOOLEAN DEFAULT 0,
    hw_accel            TEXT,                             -- CPU instr or coprocessor support
    first_published     INTEGER                           -- year
);
```

### Table: `category`
```sql
CREATE TABLE category (
    cat_id          INTEGER PRIMARY KEY,
    cat_name        TEXT NOT NULL UNIQUE,
    cat_color_hex   TEXT,       -- badge color from ALGO.md style
    cat_note        TEXT
);
```

### Table: `library`
```sql
CREATE TABLE library (
    lib_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    lib_name            TEXT NOT NULL UNIQUE,
    lang                TEXT,           -- primary implementation language
    license             TEXT,
    fips_cert           TEXT,           -- FIPS 140-2/3 certificate number or 'In-Progress'
    provider_arch       TEXT,           -- EVP, ENGINE, Provider, Plugin system name
    tls_stack           BOOLEAN DEFAULT 0,
    asn1_engine         BOOLEAN DEFAULT 0,
    cert_engine         BOOLEAN DEFAULT 0,
    hsm_support         TEXT,           -- PKCS#11, CAPI, CNG, etc.
    secure_mem          BOOLEAN DEFAULT 0,
    rng_pipeline        TEXT,
    pqc_ready           BOOLEAN DEFAULT 0,
    latest_stable       TEXT            -- version as of 2025-05
);
```

### Table: `algo_lib_map`
```sql
CREATE TABLE algo_lib_map (
    map_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    algo_fk     INTEGER NOT NULL REFERENCES algorithm(algo_id),
    lib_fk      INTEGER NOT NULL REFERENCES library(lib_id),
    api_surface TEXT,           -- e.g. EVP_aes_256_gcm, crypto_aead_aes256gcm
    hw_accel    TEXT,           -- lib-specific acceleration flags
    status      TEXT            -- 'full','partial','deprecated','planned'
);
```

### Table: `protocol_integration`
```sql
CREATE TABLE protocol_integration (
    proto_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    proto_name  TEXT NOT NULL,
    algo_fk     INTEGER NOT NULL REFERENCES algorithm(algo_id),
    role        TEXT,           -- cipher-suite, KEX, signature-alg, hash-alg, etc.
    rfc_std     TEXT
);
```

---

## 1. Category Reference Table

| cat_id | cat_name | cat_color_hex | Note |
| ---: | --- | --- | --- |
| 1 | encoding | `#2f7d4f` | Representation & radix encodings |
| 2 | checksum | `#2f7d4f` | Error-detection / integrity checksums |
| 3 | hash | `#6d5796` | Unkeyed digest functions |
| 4 | xof | `#6d5796` | Extendable-output functions |
| 5 | pw-kdf | `#6d5796` | Password / memory-hard KDFs |
| 6 | block-cipher | `#1f6f9f` | Symmetric block ciphers |
| 7 | stream-cipher | `#1f6f9f` | Symmetric stream ciphers |
| 8 | block-mode | `#1f6f9f` | Unauthenticated block cipher modes |
| 9 | aead | `#1f6f9f` | Authenticated encryption with associated data |
| 10 | mac | `#1f6f9f` | Message authentication codes |
| 11 | kdf | `#1f6f9f` | Key derivation functions (non-password) |
| 12 | key-agree | `#1f6f9f` | Key exchange / agreement / KEM |
| 13 | signature | `#1f6f9f` | Digital signature algorithms |
| 14 | pke | `#1f6f9f` | Public-key encryption / KEM (classical) |
| 15 | pqc-kem | `#8f3f62` | Post-quantum KEMs |
| 16 | pqc-sig | `#8f3f62` | Post-quantum digital signatures |
| 17 | stateful-sig | `#4b5563` | Stateful hash-based signatures |
| 18 | threshold | `#9a5b1f` | Threshold / MPC primitives |
| 19 | lightweight | `#2f6f9f` | Lightweight / constrained-device crypto |
| 20 | drbg | `#856404` | Deterministic random bit generators |
| 21 | rng | `#856404` | Random number / entropy infrastructure |
| 22 | zkp | `#6b4c9a` | Zero-knowledge proof systems |
| 23 | protocol-prim | `#5a7d9a` | Protocol framework primitives |
| 24 | pki-util | `#7d5a4c` | PKI, ASN.1, certificate utilities |
| 25 | hw-interface | `#5a6a7a` | HSM / TEE / secure-enclave interfaces |

---

## 2. Encoding & Checksum Algorithms

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 1 | base16 | hex | 1 | current | encoding | — | RFC 4648 | Representation | 1 | — | 1988 |
| 2 | base32 | — | 1 | current | encoding | — | RFC 4648 | Representation | 1 | — | 1988 |
| 3 | base32hex | — | 1 | current | encoding | — | RFC 4648 | Hex alphabet variant | 1 | — | 2006 |
| 4 | base58 | — | 1 | current | encoding | — | Bitcoin | Representation | 1 | — | 2009 |
| 5 | base58check | — | 1 | current | encoding | — | Bitcoin | With 4-byte checksum | 1 | — | 2009 |
| 6 | base62 | — | 1 | current | encoding | — | — | URL-safe | 1 | — | — |
| 7 | base64 | — | 1 | current | encoding | — | RFC 4648 | Representation | 1 | — | 1988 |
| 8 | base64url | — | 1 | current | encoding | — | RFC 4648 | URL/filename safe | 1 | — | 2006 |
| 9 | base85 | ascii85 | 1 | current | encoding | — | RFC 1924 | PostScript/PDF variant | 1 | — | 1992 |
| 10 | base91 | — | 1 | historic | encoding | — | — | High density | 1 | — | 2005 |
| 11 | bech32 | — | 1 | current | encoding | — | BIP-0173 | SegWit addresses | 1 | — | 2017 |
| 12 | bech32m | — | 1 | current | encoding | — | BIP-0350 | Bech32 variant | 1 | — | 2021 |
| 13 | pem | — | 1 | current | encoding | — | RFC 7468 | Textual envelope | 1 | — | 1993 |
| 14 | der | — | 1 | current | encoding | — | ITU-T X.690 | Binary envelope | 1 | — | 1988 |
| 15 | ber | — | 1 | legacy | encoding | — | ITU-T X.690 | Basic encoding rules | 1 | — | 1988 |
| 16 | cer | — | 1 | current | encoding | — | ITU-T X.690 | DER alias in Windows | 1 | — | — |
| 17 | pkcs7 | — | 1 | current | encoding | — | RFC 2315 | CMS envelope | 1 | — | 1991 |
| 18 | pkcs8 | — | 1 | current | encoding | — | RFC 5958 | Private-key info | 1 | — | 1993 |
| 19 | pkcs12 | pfx | 1 | current | encoding | — | RFC 7292 | Key/cert bundle | 1 | — | 1996 |
| 20 | spki | — | 1 | current | encoding | — | RFC 5280 | SubjectPublicKeyInfo | 1 | — | 1988 |
| 21 | ff70 | — | 1 | current | encoding | — | — | Representation | 1 | — | — |
| 22 | crc8 | — | 2 | current | checksum | 8-bit | — | — | 1 | — | — |
| 23 | crc16 | — | 2 | current | checksum | 16-bit | — | — | 1 | — | — |
| 24 | crc16-ccitt | — | 2 | current | checksum | 16-bit | — | — | 1 | — | — |
| 25 | crc32 | — | 2 | current | checksum | 32-bit | ISO 3309 | — | 1 | SSE4.2 | 1975 |
| 26 | crc32c | castagnoli | 2 | current | checksum | 32-bit | RFC 3385 | iSCSI / SCTP | 1 | SSE4.2 | 1993 |
| 27 | crc64 | — | 2 | current | checksum | 64-bit | ISO 3309 | — | 1 | — | — |
| 28 | crc64-ecma | — | 2 | current | checksum | 64-bit | ECMA-182 | — | 1 | — | 1992 |
| 29 | adler32 | — | 2 | current | checksum | 32-bit | RFC 1950 | zlib | 1 | — | 1995 |
| 30 | fletcher16 | — | 2 | current | checksum | 16-bit | — | — | 1 | — | 1982 |
| 31 | fletcher32 | — | 2 | current | checksum | 32-bit | — | — | 1 | — | 1982 |
| 32 | xxhash32 | — | 2 | current | checksum | 32-bit | — | Fast non-crypto | 1 | AVX2 | 2014 |
| 33 | xxhash64 | — | 2 | current | checksum | 64-bit | — | Fast non-crypto | 1 | AVX2 | 2014 |
| 34 | xxh3 | — | 2 | current | checksum | 64/128-bit | — | Fast non-crypto | 1 | AVX2 | 2020 |

---

## 3. Hash / Digest Algorithms

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 35 | md2 | — | 3 | legacy | digest | 64-bit | RFC 1319 | — | 1 | — | 1989 |
| 36 | md4 | — | 3 | legacy | digest | 64-bit | RFC 1320 | — | 1 | — | 1990 |
| 37 | md5 | — | 3 | legacy | digest | 64-bit | RFC 1321 | — | 1 | AVX2 | 1992 |
| 38 | sha0 | — | 3 | legacy | digest | 80-bit | FIPS 180 | Withdrawn | 1 | — | 1993 |
| 39 | sha1 | — | 3 | legacy | digest | 80-bit | FIPS 180-4 | Deprecated 2030 | 1 | SHA-NI | 1995 |
| 40 | sha224 | — | 3 | current | digest | 112-bit | FIPS 180-4 | — | 1 | SHA-NI | 2004 |
| 41 | sha256 | — | 3 | current | digest | 128-bit | FIPS 180-4 | — | 1 | SHA-NI | 2001 |
| 42 | sha384 | — | 3 | current | digest | 192-bit | FIPS 180-4 | — | 1 | SHA-NI | 2001 |
| 43 | sha512 | — | 3 | current | digest | 256-bit | FIPS 180-4 | — | 1 | SHA-NI | 2001 |
| 44 | sha512-224 | sha512/224 | 3 | current | digest | 112-bit | FIPS 180-4 | — | 1 | SHA-NI | 2012 |
| 45 | sha512-256 | sha512/256 | 3 | current | digest | 128-bit | FIPS 180-4 | — | 1 | SHA-NI | 2012 |
| 46 | sha3-224 | — | 3 | current | digest | 112-bit | FIPS 202 | Keccak-f[1600] | 1 | — | 2015 |
| 47 | sha3-256 | — | 3 | current | digest | 128-bit | FIPS 202 | Keccak-f[1600] | 1 | — | 2015 |
| 48 | sha3-384 | — | 3 | current | digest | 192-bit | FIPS 202 | Keccak-f[1600] | 1 | — | 2015 |
| 49 | sha3-512 | — | 3 | current | digest | 256-bit | FIPS 202 | Keccak-f[1600] | 1 | — | 2015 |
| 50 | keccak256 | — | 3 | current | digest | 128-bit | — | Ethereum precompile | 1 | — | 2012 |
| 51 | keccak512 | — | 3 | current | digest | 256-bit | — | — | 1 | — | 2012 |
| 52 | shake128 | — | 4 | current | xof | 128-bit | FIPS 202 | XOF | 1 | — | 2015 |
| 53 | shake256 | — | 4 | current | xof | 256-bit | FIPS 202 | XOF | 1 | — | 2015 |
| 54 | cshake128 | — | 4 | current | xof | 128-bit | SP 800-185 | Customizable XOF | 1 | — | 2016 |
| 55 | cshake256 | — | 4 | current | xof | 256-bit | SP 800-185 | Customizable XOF | 1 | — | 2016 |
| 56 | kmac128 | — | 4 | current | xof | 128-bit | SP 800-185 | KMAC / XOF | 1 | — | 2016 |
| 57 | kmac256 | — | 4 | current | xof | 256-bit | SP 800-185 | KMAC / XOF | 1 | — | 2016 |
| 58 | kmacxof128 | — | 4 | current | xof | 128-bit | SP 800-185 | KMAC128 XOF mode | 1 | — | 2016 |
| 59 | kmacxof256 | — | 4 | current | xof | 256-bit | SP 800-185 | KMAC256 XOF mode | 1 | — | 2016 |
| 60 | parallelhash128 | — | 4 | current | xof | 128-bit | SP 800-185 | ParallelHash | 1 | — | 2016 |
| 61 | parallelhash256 | — | 4 | current | xof | 256-bit | SP 800-185 | ParallelHash | 1 | — | 2016 |
| 62 | tuplehash128 | — | 4 | current | xof | 128-bit | SP 800-185 | TupleHash | 1 | — | 2016 |
| 63 | tuplehash256 | — | 4 | current | xof | 256-bit | SP 800-185 | TupleHash | 1 | — | 2016 |
| 64 | kangarootwelve | k12 | 4 | current | xof | 128-bit | — | Keccak-derived tree | 1 | AVX2 | 2016 |
| 65 | marsupilami14 | m14 | 4 | current | xof | 256-bit | — | Keccak-derived tree | 1 | — | 2016 |
| 66 | blake2b | — | 3 | current | digest | 512-bit | RFC 7693 | — | 1 | AVX2 | 2012 |
| 67 | blake2s | — | 3 | current | digest | 256-bit | RFC 7693 | — | 1 | AVX2 | 2012 |
| 68 | blake2bp | — | 3 | current | digest | 512-bit | — | Parallel BLAKE2b | 1 | AVX2 | — |
| 69 | blake2sp | — | 3 | current | digest | 256-bit | — | Parallel BLAKE2s | 1 | AVX2 | — |
| 70 | blake3 | — | 3 | current | digest | 256-bit | — | Tree hash / XOF | 1 | AVX2 | 2020 |
| 71 | skein256 | — | 3 | current | digest | 128-bit | — | Threefish-based | 1 | — | 2008 |
| 72 | skein512 | — | 3 | current | digest | 256-bit | — | Threefish-based | 1 | — | 2008 |
| 73 | skein1024 | — | 3 | current | digest | 512-bit | — | Threefish-based | 1 | — | 2008 |
| 74 | sm3 | — | 3 | current | digest | 128-bit | GB/T 32905 | Chinese national hash | 1 | — | 2010 |
| 75 | gost-r-34.11-94 | gost94 | 3 | legacy | digest | 128-bit | GOST R 34.11-94 | Russian hash | 1 | — | 1994 |
| 76 | streebog256 | gost2012-256 | 3 | current | digest | 128-bit | GOST R 34.11-2012 | Russian hash | 1 | — | 2012 |
| 77 | streebog512 | gost2012-512 | 3 | current | digest | 256-bit | GOST R 34.11-2012 | Russian hash | 1 | — | 2012 |
| 78 | ripemd128 | — | 3 | legacy | digest | 64-bit | — | — | 1 | — | 1996 |
| 79 | ripemd160 | — | 3 | legacy | digest | 80-bit | — | Bitcoin legacy | 1 | — | 1996 |
| 80 | ripemd256 | — | 3 | legacy | digest | 128-bit | — | — | 1 | — | 1996 |
| 81 | ripemd320 | — | 3 | legacy | digest | 160-bit | — | — | 1 | — | 1996 |
| 82 | tiger | — | 3 | legacy | digest | 96-bit | — | — | 1 | — | 1996 |
| 83 | whirlpool | — | 3 | legacy | digest | 256-bit | ISO/IEC 10118-3 | — | 1 | — | 2000 |
| 84 | has160 | — | 3 | legacy | digest | 80-bit | — | Korean hash | 1 | — | 1998 |
| 85 | nt | nthash | 3 | legacy | digest | 64-bit | — | Windows NT hash | 1 | — | 1993 |
| 86 | lmhash | — | 3 | legacy | digest | 43-bit | — | Windows LAN Manager | 1 | — | 1987 |
| 87 | md6 | — | 3 | historic | digest | variable | — | Merkle tree hash | 1 | — | 2008 |
| 88 | radio-gatun | — | 3 | historic | digest | variable | — | — | 1 | — | 2006 |
| 89 | groestl | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 90 | jh | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 91 | cubehash | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 92 | echo | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 93 | simd | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 94 | fugue | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 95 | hamsi | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 96 | luffa | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 97 | shabal | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 98 | bmw | blue-midnight-wish | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |
| 99 | shavite3 | — | 3 | historic | digest | variable | — | SHA-3 finalist | 1 | — | 2008 |

---

## 4. Password KDFs / Password Hashing

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 100 | pbkdf2 | — | 5 | current | pw-kdf | variable | RFC 2898 / SP 800-132 | — | 0 | — | 2000 |
| 101 | pbkdf2-hmac-sha1 | — | 5 | legacy | pw-kdf | 80-bit | — | Deprecated | 0 | — | — |
| 102 | pbkdf2-hmac-sha256 | — | 5 | current | pw-kdf | 128-bit | — | — | 0 | — | — |
| 103 | pbkdf2-hmac-sha512 | — | 5 | current | pw-kdf | 256-bit | — | — | 0 | — | — |
| 104 | bcrypt | — | 5 | current | pw-kdf | 184-bit | OpenBSD | Eksblowfish | 0 | — | 1999 |
| 105 | scrypt | — | 5 | current | pw-kdf | variable | RFC 7914 | Memory-hard | 0 | — | 2009 |
| 106 | argon2d | — | 5 | current | pw-kdf | variable | RFC 9106 / PHC winner | Data-dependent | 0 | — | 2015 |
| 107 | argon2i | — | 5 | current | pw-kdf | variable | RFC 9106 | Data-independent | 0 | — | 2015 |
| 108 | argon2id | — | 5 | current | pw-kdf | variable | RFC 9106 | Hybrid | 0 | — | 2015 |
| 109 | yescrypt | — | 5 | current | pw-kdf | variable | — | PHC finalist | 0 | — | 2015 |
| 110 | lyra2 | — | 5 | current | pw-kdf | variable | — | PHC finalist | 0 | — | 2014 |
| 111 | catena | — | 5 | historic | pw-kdf | variable | — | PHC finalist | 0 | — | 2013 |
| 112 | balloon | — | 5 | current | pw-kdf | variable | — | Memory-hard | 0 | — | 2016 |
| 113 | pomelo | — | 5 | historic | pw-kdf | variable | — | PHC submission | 0 | — | 2014 |
| 114 | makwa | — | 5 | historic | pw-kdf | variable | — | PHC submission | 0 | — | 2014 |
| 115 | bsdicrypt | — | 5 | legacy | pw-kdf | 36-bit | — | — | 0 | — | 1979 |
| 116 | md5crypt | — | 5 | legacy | pw-kdf | 64-bit | — | — | 0 | — | 1994 |
| 117 | sha256crypt | — | 5 | legacy | pw-kdf | 128-bit | — | — | 0 | — | 2007 |
| 118 | sha512crypt | — | 5 | legacy | pw-kdf | 256-bit | — | — | 0 | — | 2007 |

---

## 5. Symmetric Block Ciphers

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 119 | aes-128 | rijndael-128 | 6 | current | block-cipher | 128-bit | FIPS 197 | — | 0 | AES-NI | 2001 |
| 120 | aes-192 | rijndael-192 | 6 | current | block-cipher | 192-bit | FIPS 197 | — | 0 | AES-NI | 2001 |
| 121 | aes-256 | rijndael-256 | 6 | current | block-cipher | 256-bit | FIPS 197 | — | 0 | AES-NI | 2001 |
| 122 | aria-128 | — | 6 | current | block-cipher | 128-bit | RFC 5794 | Korean standard | 0 | — | 2003 |
| 123 | aria-192 | — | 6 | current | block-cipher | 192-bit | RFC 5794 | — | 0 | — | 2003 |
| 124 | aria-256 | — | 6 | current | block-cipher | 256-bit | RFC 5794 | — | 0 | — | 2003 |
| 125 | camellia-128 | — | 6 | current | block-cipher | 128-bit | RFC 3713 / ISO | NTT/Mitsubishi | 0 | — | 2000 |
| 126 | camellia-192 | — | 6 | current | block-cipher | 192-bit | RFC 3713 | — | 0 | — | 2000 |
| 127 | camellia-256 | — | 6 | current | block-cipher | 256-bit | RFC 3713 | — | 0 | — | 2000 |
| 128 | seed | — | 6 | current | block-cipher | 128-bit | RFC 4269 | Korean standard | 0 | — | 1998 |
| 129 | sm4 | sms4 | 6 | current | block-cipher | 128-bit | GB/T 32907 | Chinese standard | 0 | — | 2006 |
| 130 | kuznyechik | grasshopper | 6 | current | block-cipher | 128-bit | GOST R 34.12-2015 | Russian standard | 0 | — | 2015 |
| 131 | magma | gost89 | 6 | legacy | block-cipher | 64-bit | GOST 28147-89 | Russian legacy | 0 | — | 1989 |
| 132 | 3des | tdes,dea-3 | 6 | legacy | block-cipher | 80-bit | SP 800-67 Rev2 | Withdrawn 2024 | 0 | — | 1978 |
| 133 | des | dea-1 | 6 | legacy | block-cipher | 56-bit | FIPS 46-3 | Withdrawn | 0 | — | 1977 |
| 134 | blowfish | — | 6 | legacy | block-cipher | 32-448-bit | — | 64-bit block | 0 | — | 1993 |
| 135 | twofish | — | 6 | historic | block-cipher | 128-256-bit | — | AES finalist | 0 | — | 1998 |
| 136 | serpent | — | 6 | historic | block-cipher | 128-256-bit | — | AES finalist | 0 | — | 1998 |
| 137 | cast5 | cast-128 | 6 | legacy | block-cipher | 40-128-bit | RFC 2144 | 64-bit block | 0 | — | 1996 |
| 138 | cast6 | cast-256 | 6 | legacy | block-cipher | 128-256-bit | RFC 2612 | 128-bit block | 0 | — | 1998 |
| 139 | idea | — | 6 | legacy | block-cipher | 128-bit | — | 64-bit block | 0 | — | 1991 |
| 140 | rc2 | — | 6 | legacy | block-cipher | 40-128-bit | RFC 2268 | 64-bit block | 0 | — | 1987 |
| 141 | rc5 | — | 6 | legacy | block-cipher | variable | RFC 2040 | 64-bit block | 0 | — | 1994 |
| 142 | rc6 | — | 6 | historic | block-cipher | 128-256-bit | — | AES finalist | 0 | — | 1998 |
| 143 | misty1 | — | 6 | legacy | block-cipher | 128-bit | RFC 2994 | 64-bit block | 0 | — | 1995 |
| 144 | kasumi | — | 6 | legacy | block-cipher | 128-bit | 3GPP | A5/3,Gf8 | 0 | — | 1998 |
| 145 | safer | — | 6 | historic | block-cipher | 40-128-bit | — | — | 0 | — | 1993 |
| 146 | skipjack | — | 6 | legacy | block-cipher | 80-bit | — | NSA Clipper | 0 | — | 1993 |
| 147 | present | — | 6 | current | block-cipher | 80/128-bit | ISO/IEC 29192-2 | Ultra-lightweight | 0 | — | 2007 |
| 148 | led | — | 6 | current | block-cipher | 64/128-bit | — | Lightweight | 0 | — | 2011 |
| 149 | piccolo | — | 6 | current | block-cipher | 80/128-bit | — | Lightweight | 0 | — | 2011 |
| 150 | clefia | — | 6 | current | block-cipher | 128/192/256-bit | ISO/IEC 29192-2 | Sony | 0 | — | 2007 |
| 151 | threefish-256 | — | 6 | current | block-cipher | 256-bit | — | Skein companion | 0 | — | 2008 |
| 152 | threefish-512 | — | 6 | current | block-cipher | 512-bit | — | Skein companion | 0 | — | 2008 |
| 153 | threefish-1024 | — | 6 | current | block-cipher | 1024-bit | — | Skein companion | 0 | — | 2008 |
| 154 | speck | — | 6 | legacy | block-cipher | 64-256-bit | — | NSA; deprecated | 0 | — | 2013 |
| 155 | simon | — | 6 | legacy | block-cipher | 64-256-bit | — | NSA; deprecated | 0 | — | 2013 |
| 156 | xtea | — | 6 | legacy | block-cipher | 128-bit | — | 64-bit block | 0 | — | 1997 |
| 157 | tea | — | 6 | legacy | block-cipher | 128-bit | — | 64-bit block | 0 | — | 1994 |
| 158 | gost28147 | — | 6 | legacy | block-cipher | 256-bit | GOST 28147-89 | — | 0 | — | 1989 |
| 159 | anubis | — | 6 | historic | block-cipher | 128-320-bit | — | NESSIE | 0 | — | 2000 |
| 160 | khazad | — | 6 | historic | block-cipher | 128-bit | — | NESSIE | 0 | — | 2000 |
| 161 | noekeon | — | 6 | historic | block-cipher | 128-bit | — | NESSIE | 0 | — | 2000 |

---

## 6. Stream Ciphers

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 162 | chacha20 | — | 7 | current | stream-cipher | 256-bit | RFC 8439 | — | 1 | AVX2 | 2008 |
| 163 | xchacha20 | — | 7 | current | stream-cipher | 256-bit | RFC 8439 | Extended nonce | 1 | AVX2 | 2018 |
| 164 | salsa20 | — | 7 | current | stream-cipher | 256-bit | — | — | 1 | — | 2005 |
| 165 | xsalsa20 | — | 7 | current | stream-cipher | 256-bit | — | Extended nonce | 1 | — | 2008 |
| 166 | chacha8 | — | 7 | current | stream-cipher | 256-bit | — | Reduced round | 1 | AVX2 | — |
| 167 | chacha12 | — | 7 | current | stream-cipher | 256-bit | — | Reduced round | 1 | AVX2 | — |
| 168 | rc4 | arcfour | 7 | legacy | stream-cipher | 40-256-bit | — | Deprecated | 1 | — | 1987 |
| 169 | hc128 | — | 7 | current | stream-cipher | 128-bit | — | eSTREAM | 1 | — | 2008 |
| 170 | hc256 | — | 7 | current | stream-cipher | 256-bit | — | eSTREAM | 1 | — | 2008 |
| 171 | rabbit | — | 7 | current | stream-cipher | 128-bit | — | eSTREAM | 1 | — | 2003 |
| 172 | sosemanuk | — | 7 | current | stream-cipher | 128-bit | — | eSTREAM | 1 | — | 2005 |
| 173 | grainv1 | — | 7 | legacy | stream-cipher | 80-bit | — | eSTREAM | 1 | — | 2004 |
| 174 | grain128 | — | 7 | current | stream-cipher | 128-bit | — | eSTREAM | 1 | — | 2006 |
| 175 | mickeyv2 | — | 7 | legacy | stream-cipher | 80-bit | — | eSTREAM | 1 | — | 2004 |
| 176 | trivium | — | 7 | legacy | stream-cipher | 80-bit | — | eSTREAM | 1 | — | 2005 |
| 177 | zuc | 128-eea3 | 7 | current | stream-cipher | 128-bit | 3GPP | LTE/5G cipher | 1 | — | 2011 |
| 178 | snow3g | 128-eea2 | 7 | current | stream-cipher | 128-bit | 3GPP | LTE cipher | 1 | — | 2006 |
| 179 | aes-ctr-drbg | — | 7 | current | stream-cipher | 128/256-bit | SP 800-90A | DRBG stream | 1 | AES-NI | — |
| 180 | isaac | — | 7 | legacy | stream-cipher | variable | — | — | 1 | — | 1996 |
| 181 | isaac+ | — | 7 | legacy | stream-cipher | variable | — | — | 1 | — | 1999 |
| 182 | panama | — | 7 | historic | stream-cipher | 256-bit | — | — | 1 | — | 1998 |
| 183 | wake | — | 7 | legacy | stream-cipher | 256-bit | — | — | 1 | — | 1993 |
| 184 | seal | — | 7 | legacy | stream-cipher | 160-bit | — | — | 1 | — | 1994 |
| 185 | a5/1 | — | 7 | legacy | stream-cipher | 54-bit | GSM | Broken | 1 | — | 1987 |
| 186 | a5/2 | — | 7 | legacy | stream-cipher | 16-bit | GSM | Broken | 1 | — | 1987 |
| 187 | e0 | — | 7 | legacy | stream-cipher | variable | Bluetooth | Broken | 1 | — | 1994 |

---

## 7. Block Cipher Modes (Unauthenticated)

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 188 | ecb | — | 8 | legacy | block-mode | — | SP 800-38A | Electronic Codebook | 1 | AES-NI | 1981 |
| 189 | cbc | — | 8 | legacy | block-mode | — | SP 800-38A | Cipher Block Chaining | 1 | AES-NI | 1976 |
| 190 | cfb | — | 8 | legacy | block-mode | — | SP 800-38A | Cipher Feedback | 1 | AES-NI | 1976 |
| 191 | cfb1 | — | 8 | legacy | block-mode | — | SP 800-38A | 1-bit CFB | 1 | AES-NI | — |
| 192 | cfb8 | — | 8 | legacy | block-mode | — | SP 800-38A | 8-bit CFB | 1 | AES-NI | — |
| 193 | ofb | — | 8 | legacy | block-mode | — | SP 800-38A | Output Feedback | 1 | AES-NI | 1980 |
| 194 | ctr | — | 8 | current | block-mode | — | SP 800-38A | Counter | 1 | AES-NI | 1979 |
| 195 | xts | — | 8 | current | block-mode | — | SP 800-38E / IEEE 1619 | Disk encryption | 1 | AES-NI | 2007 |
| 196 | cbc-cs1 | — | 8 | current | block-mode | — | SP 800-38A Add | Ciphertext stealing | 1 | AES-NI | 2010 |
| 197 | cbc-cs2 | — | 8 | current | block-mode | — | SP 800-38A Add | Ciphertext stealing | 1 | AES-NI | 2010 |
| 198 | cbc-cs3 | — | 8 | current | block-mode | — | SP 800-38A Add | Ciphertext stealing | 1 | AES-NI | 2010 |

---

## 8. AEAD Algorithms

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 199 | aes-gcm | gcm | 9 | current | aead | 128-bit | SP 800-38D / RFC 5116 | — | 1 | AES-NI+PCLMUL | 2004 |
| 200 | aes-ccm | ccm | 9 | current | aead | 128-bit | SP 800-38C / RFC 5116 | — | 1 | AES-NI | 2002 |
| 201 | aes-gcm-siv | — | 9 | current | aead | 128-bit | RFC 8452 | Misuse-resistant | 1 | AES-NI+PCLMUL | 2017 |
| 202 | aes-siv | siv-aes | 9 | current | aead | 128-bit | RFC 5297 | Synthetic IV | 0 | AES-NI | 2008 |
| 203 | aes-ocb | ocb | 9 | current | aead | 128-bit | RFC 7253 | Offset Codebook | 1 | AES-NI | 2001 |
| 204 | aes-eax | eax | 9 | current | aead | 128-bit | — | — | 1 | AES-NI | 2003 |
| 205 | aes-kw | keywrap | 9 | current | aead | 128-bit | SP 800-38F | Key Wrap | 0 | AES-NI | 2001 |
| 206 | aes-kwp | keywrap-pad | 9 | current | aead | 128-bit | SP 800-38F | Key Wrap w/ Padding | 0 | AES-NI | 2008 |
| 207 | aes-gmac | gmac | 9 | current | aead | 128-bit | SP 800-38D | Auth only | 1 | AES-NI+PCLMUL | 2004 |
| 208 | aes-xpn | — | 9 | current | aead | 128-bit | IEEE 802.1AEbw | MACsec XPN | 1 | AES-NI+PCLMUL | 2018 |
| 209 | aes-fpe-ff1 | — | 9 | current | aead | 128-bit | SP 800-38G | Format-preserving | 0 | AES-NI | 2016 |
| 210 | aes-fpe-ff3-1 | ff3 | 9 | current | aead | 128-bit | SP 800-38G | Format-preserving | 0 | AES-NI | 2016 |
| 211 | chacha20-poly1305 | — | 9 | current | aead | 256-bit | RFC 8439 | — | 1 | AVX2 | 2015 |
| 212 | xchacha20-poly1305 | — | 9 | current | aead | 256-bit | RFC 8439 | Extended nonce | 1 | AVX2 | 2018 |
| 213 | aegis128l | — | 9 | current | aead | 128-bit | — | High perf | 1 | AES-NI | 2013 |
| 214 | aegis256 | — | 9 | current | aead | 256-bit | — | High perf | 1 | AES-NI | 2013 |
| 215 | deoxys-ii | — | 9 | current | aead | 128-bit | CAESAR finalist | Misuse-resistant | 1 | AES-NI | 2014 |
| 216 | morus | — | 9 | historic | aead | 128-bit | CAESAR finalist | — | 1 | — | 2014 |
| 217 | ocb3 | — | 9 | current | aead | 128-bit | RFC 7253 | OCB v3 | 1 | AES-NI | 2011 |
| 218 | kccm | — | 9 | current | aead | 128-bit | — | KIASU variant | 1 | AES-NI | 2014 |
| 219 | kiasu | — | 9 | historic | aead | 128-bit | — | CAESAR | 1 | AES-NI | 2014 |
| 220 | marble | — | 9 | historic | aead | 128-bit | — | CAESAR | 1 | — | 2014 |
| 221 | ascon-aead128 | — | 9 | current | aead | 128-bit | SP 800-232 | NIST LWC winner | 1 | — | 2023 |
| 222 | ascon-aead128a | — | 9 | current | aead | 128-bit | SP 800-232 | NIST LWC | 1 | — | 2023 |
| 223 | ascon-80pq | — | 9 | current | aead | 80-bit | — | Legacy LWC variant | 1 | — | 2014 |
| 224 | elephant-dumbo | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 225 | elephant-jumbo | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 226 | gift-cofb | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 227 | grain-128aead | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 228 | isap-a-128a | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 229 | isap-k-128a | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 230 | photon-beetle | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 231 | romulus | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 232 | sparkle-schwaemm | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 233 | tinyjambu | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 234 | xoodyak | — | 9 | historic | aead | 128-bit | NIST LWC finalist | — | 1 | — | 2019 |
| 235 | colm | — | 9 | historic | aead | 128-bit | — | CAESAR | 1 | AES-NI | 2014 |
| 236 | silc | — | 9 | historic | aead | 128-bit | — | CAESAR | 1 | AES-NI | 2014 |

---

## 9. MAC Algorithms

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 237 | hmac | — | 10 | current | mac | variable | RFC 2104 | — | 1 | — | 1997 |
| 238 | hmac-sha256 | — | 10 | current | mac | 128-bit | — | — | 1 | SHA-NI | — |
| 239 | hmac-sha512 | — | 10 | current | mac | 256-bit | — | — | 1 | SHA-NI | — |
| 240 | hmac-sha3-256 | — | 10 | current | mac | 128-bit | — | — | 1 | — | — |
| 241 | hmac-blake2b | — | 10 | current | mac | 512-bit | RFC 7693 | — | 1 | AVX2 | — |
| 242 | hmac-blake2s | — | 10 | current | mac | 256-bit | RFC 7693 | — | 1 | AVX2 | — |
| 243 | aes-cmac | cmac | 10 | current | mac | 128-bit | SP 800-38B | — | 1 | AES-NI | 2005 |
| 244 | aes-pmac | pmac | 10 | current | mac | 128-bit | — | Parallelizable | 1 | AES-NI | 2002 |
| 245 | xcbc-mac | — | 10 | legacy | mac | 128-bit | RFC 3566 | — | 1 | AES-NI | 2003 |
| 246 | vmac | — | 10 | current | mac | 128-bit | — | Universal hash | 1 | — | 2007 |
| 247 | umac | — | 10 | current | mac | 128-bit | RFC 4418 | Universal hash | 1 | — | 1999 |
| 248 | poly1305 | — | 10 | current | mac | 128-bit | RFC 8439 | — | 1 | AVX2 | 2005 |
| 249 | siphash | — | 10 | current | mac | 64/128-bit | — | Short-input MAC | 1 | — | 2012 |
| 250 | siphash-2-4 | — | 10 | current | mac | 64-bit | — | Default variant | 1 | — | 2012 |
| 251 | siphash-4-8 | — | 10 | current | mac | 128-bit | — | High security | 1 | — | 2012 |
| 252 | kmac128 | — | 10 | current | mac | 128-bit | SP 800-185 | Keccak-based | 1 | — | 2016 |
| 253 | kmac256 | — | 10 | current | mac | 256-bit | SP 800-185 | Keccak-based | 1 | — | 2016 |
| 254 | blake2b-mac | keyed-blake2b | 10 | current | mac | 512-bit | RFC 7693 | Keyed hashing | 1 | AVX2 | 2012 |
| 255 | blake2s-mac | keyed-blake2s | 10 | current | mac | 256-bit | RFC 7693 | Keyed hashing | 1 | AVX2 | 2012 |
| 256 | blake3-mac | keyed-blake3 | 10 | current | mac | 256-bit | — | Keyed hashing | 1 | AVX2 | 2020 |
| 257 | ascon-mac | — | 10 | current | mac | 128-bit | SP 800-232 | NIST LWC | 1 | — | 2023 |
| 258 | ascon-prf | — | 10 | current | mac | 128-bit | SP 800-232 | NIST LWC PRF | 1 | — | 2023 |
| 259 | cbc-mac | — | 10 | legacy | mac | 64-bit | — | Deprecated | 1 | AES-NI | 1980s |
| 260 | des-mac | — | 10 | legacy | mac | 56-bit | — | Deprecated | 1 | — | — |
| 261 | ghash | — | 10 | current | mac | 128-bit | — | GCM universal hash | 1 | PCLMUL | 2004 |
| 262 | kdf1 | — | 10 | legacy | mac | — | IEEE 1363 | — | 0 | — | 2000 |

---

## 10. Key Derivation Functions (Non-Password)

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 263 | hkdf | — | 11 | current | kdf | variable | RFC 5869 | Extract-then-Expand | 0 | — | 2010 |
| 264 | hkdf-expand | — | 11 | current | kdf | variable | RFC 5869 | Expand only | 0 | — | 2010 |
| 265 | hkdf-extract | — | 11 | current | kdf | variable | RFC 5869 | Extract only | 0 | — | 2010 |
| 266 | hkdf-expand-label | — | 11 | current | kdf | variable | RFC 8446 | TLS 1.3 helper | 0 | — | 2018 |
| 267 | kdf-tls12 | tls12-prf | 11 | current | kdf | variable | RFC 5246 | TLS 1.2 PRF | 0 | — | 2008 |
| 268 | kdf-tls13 | tls13-kdf | 11 | current | kdf | variable | RFC 8446 | TLS 1.3 HKDF | 0 | — | 2018 |
| 269 | kdf-ssh | ssh-kdf | 11 | current | kdf | variable | RFC 4253 | SSH KDF | 0 | — | 2006 |
| 270 | kdf-ikev1 | — | 11 | current | kdf | variable | RFC 2409 | IKEv1 KDF | 0 | — | 1998 |
| 271 | kdf-ikev2 | — | 11 | current | kdf | variable | RFC 4306 | IKEv2 KDF | 0 | — | 2005 |
| 272 | kdf-srtp | — | 11 | current | kdf | variable | RFC 3711 | SRTP KDF | 0 | — | 2004 |
| 273 | kdf-sp800-108 | kdf-ctr,kdf-feedback,kdf-pipeline | 11 | current | kdf | variable | SP 800-108r1 | Counter/Feedback | 0 | — | 2009 |
| 274 | kda-onestep | — | 11 | current | kdf | variable | SP 800-56C Rev 2 | One-step KDF | 0 | — | 2018 |
| 275 | kda-twostep | — | 11 | current | kdf | variable | SP 800-56C Rev 2 | Two-step KDF | 0 | — | 2018 |
| 276 | concat-kdf | — | 11 | current | kdf | variable | NIST / JOSE | ECIES/JWE | 0 | — | 2009 |
| 277 | x942-kdf | — | 11 | current | kdf | variable | ANSI X9.42 | CMS/PKCS | 0 | — | 2003 |
| 278 | x963-kdf | ansi-x963 | 11 | current | kdf | variable | ANSI X9.63 | ECC KDF | 0 | — | 2001 |
| 279 | noise-kdf | — | 11 | current | kdf | variable | Noise Framework | — | 0 | — | 2018 |
| 280 | bip32-kdf | — | 11 | current | kdf | variable | BIP-0032 | HD wallet | 0 | — | 2012 |
| 281 | slip10 | — | 11 | current | kdf | variable | SLIP-0010 | HD wallet | 0 | — | 2017 |
| 282 | sskdf | — | 11 | current | kdf | variable | SP 800-56C | Single-step | 0 | — | 2018 |
| 283 | ecdh-kdf | — | 11 | current | kdf | variable | SEC 1 | ANSI X9.63 variant | 0 | — | 2000 |
| 284 | cmkdf | — | 11 | planned | kdf | variable | — | Committing KDF | 0 | — | 2023 |
| 285 | me-kdf | — | 11 | planned | kdf | variable | — | Multi-Extract | 0 | — | 2023 |

---

## 11. Key Agreement / KEM / Public-Key Encryption

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 286 | dh | diffie-hellman | 12 | current | key-agree | 112-256-bit | RFC 2631 / SP 800-56A | Finite-field | 0 | — | 1976 |
| 287 | dhp | safe-prime-dh | 12 | current | key-agree | variable | RFC 7919 | TLS FFDHE | 0 | — | 2016 |
| 288 | ecdh | — | 12 | current | key-agree | 128-256-bit | SP 800-56A | Elliptic-curve | 0 | — | 1985 |
| 289 | x25519 | curve25519 | 12 | current | key-agree | 128-bit | RFC 7748 | Montgomery DH | 0 | — | 2006 |
| 290 | x448 | curve448 | 12 | current | key-agree | 224-bit | RFC 7748 | Montgomery DH | 0 | — | 2015 |
| 291 | ecmqv | — | 12 | legacy | key-agree | 128-256-bit | — | MQV variant | 0 | — | 1995 |
| 292 | x3dh | — | 12 | current | key-agree | 128-bit | Signal Spec | Extended 3DH | 0 | — | 2016 |
| 293 | hpke | — | 12 | current | kem | 128-256-bit | RFC 9180 | Hybrid PKE | 0 | — | 2022 |
| 294 | ecies | — | 12 | current | pke | 128-256-bit | SEC 1 / ISO 18033-2 | Elliptic-curve PKE | 0 | — | 2001 |
| 295 | rsa-oaep | — | 14 | current | pke | 128-256-bit | RFC 8017 | PKCS#1 v2.2 | 0 | — | 1998 |
| 296 | rsa-pkcs1v15-enc | — | 14 | legacy | pke | 80-256-bit | RFC 8017 | PKCS#1 v1.5 | 0 | — | 1993 |
| 297 | elgamal | — | 14 | legacy | pke | variable | — | — | 0 | — | 1985 |
| 298 | csidh | — | 12 | planned | key-agree | 128-bit | — | Isogeny-based | 0 | — | 2018 |
| 299 | sike | — | 12 | historic | key-agree | variable | — | Broken 2022 | 0 | — | 2011 |
| 300 | frodokem | — | 15 | current | pqc-kem | 128-256-bit | — | Conservative lattice | 0 | — | 2016 |
| 301 | kyber | ml-kem | 15 | current | pqc-kem | 128-256-bit | FIPS 203 | NIST standard | 0 | — | 2017 |
| 302 | ml-kem-512 | kyber512 | 15 | current | pqc-kem | 128-bit | FIPS 203 | NIST Level 1 | 0 | — | 2024 |
| 303 | ml-kem-768 | kyber768 | 15 | current | pqc-kem | 192-bit | FIPS 203 | NIST Level 3 | 0 | — | 2024 |
| 304 | ml-kem-1024 | kyber1024 | 15 | current | pqc-kem | 256-bit | FIPS 203 | NIST Level 5 | 0 | — | 2024 |
| 305 | ntru | — | 15 | current | pqc-kem | variable | IEEE 1363.1 | Lattice | 0 | — | 1996 |
| 306 | ntruprime | — | 15 | current | pqc-kem | variable | — | Lattice | 0 | — | 2016 |
| 307 | sntrup761 | — | 15 | current | pqc-kem | 256-bit | — | Streamlined NTRU Prime | 0 | — | 2019 |
| 308 | classic-mceliece | — | 15 | current | pqc-kem | 256-bit | — | Code-based | 0 | — | 1978 |
| 309 | mceliece-348864 | — | 15 | current | pqc-kem | 128-bit | — | Code-based | 0 | — | 2017 |
| 310 | mceliece-348864f | — | 15 | current | pqc-kem | 128-bit | — | Code-based | 0 | — | 2017 |
| 311 | mceliece-460896 | — | 15 | current | pqc-kem | 192-bit | — | Code-based | 0 | — | 2017 |
| 312 | mceliece-460896f | — | 15 | current | pqc-kem | 192-bit | — | Code-based | 0 | — | 2017 |
| 313 | mceliece-6688128 | — | 15 | current | pqc-kem | 256-bit | — | Code-based | 0 | — | 2017 |
| 314 | mceliece-6688128f | — | 15 | current | pqc-kem | 256-bit | — | Code-based | 0 | — | 2017 |
| 315 | mceliece-6960119 | — | 15 | current | pqc-kem | 256-bit | — | Code-based | 0 | — | 2017 |
| 316 | mceliece-6960119f | — | 15 | current | pqc-kem | 256-bit | — | Code-based | 0 | — | 2017 |
| 317 | mceliece-8192128 | — | 15 | current | pqc-kem | 256-bit | — | Code-based | 0 | — | 2017 |
| 318 | mceliece-8192128f | — | 15 | current | pqc-kem | 256-bit | — | Code-based | 0 | — | 2017 |
| 319 | bike-1 | — | 15 | current | pqc-kem | 128-bit | — | Code-based | 0 | — | 2017 |
| 320 | bike-3 | — | 15 | current | pqc-kem | 192-bit | — | Code-based | 0 | — | 2017 |
| 321 | bike-5 | — | 15 | current | pqc-kem | 256-bit | — | Code-based | 0 | — | 2017 |
| 322 | hqc-128 | — | 15 | planned | pqc-kem | 128-bit | — | NIST backup KEM | 0 | — | 2017 |
| 323 | hqc-192 | — | 15 | planned | pqc-kem | 192-bit | — | NIST backup KEM | 0 | — | 2017 |
| 324 | hqc-256 | — | 15 | planned | pqc-kem | 256-bit | — | NIST backup KEM | 0 | — | 2017 |
| 325 | ntruhps2048677 | — | 15 | current | pqc-kem | 192-bit | — | NTRU submission | 0 | — | 2019 |
| 326 | ntruhps4096821 | — | 15 | current | pqc-kem | 256-bit | — | NTRU submission | 0 | — | 2019 |
| 327 | ntruhrss701 | — | 15 | current | pqc-kem | 192-bit | — | NTRU submission | 0 | — | 2019 |

---

## 12. Digital Signature Algorithms

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 328 | rsa-pkcs1v15-sign | — | 13 | legacy | signature | 80-256-bit | RFC 8017 | PKCS#1 v1.5 | 0 | — | 1993 |
| 329 | rsa-pss | rsassa-pss | 13 | current | signature | 128-256-bit | RFC 8017 | Probabilistic | 0 | — | 1998 |
| 330 | dsa | — | 13 | legacy | signature | 80-256-bit | FIPS 186-4 | Withdrawn | 0 | — | 1991 |
| 331 | ecdsa | — | 13 | current | signature | 128-256-bit | FIPS 186-5 | — | 0 | — | 1999 |
| 332 | det-ecdsa | — | 13 | current | signature | 128-256-bit | RFC 6979 | Deterministic | 0 | — | 2013 |
| 333 | ecdsa-recoverable | — | 13 | current | signature | 128-bit | — | secp256k1 | 0 | — | 2012 |
| 334 | ed25519 | — | 13 | current | signature | 128-bit | RFC 8032 | EdDSA | 0 | — | 2011 |
| 335 | ed448 | — | 13 | current | signature | 224-bit | RFC 8032 | EdDSA | 0 | — | 2015 |
| 336 | sr25519 | — | 13 | current | signature | 128-bit | — | Schnorrkel/Ristretto | 0 | — | 2019 |
| 337 | sm2-sign | — | 13 | current | signature | 128-bit | GB/T 32918 | Chinese standard | 0 | — | 2010 |
| 338 | gost-r-34.10-2012 | gost2012-sign | 13 | current | signature | 128-256-bit | GOST R 34.10-2012 | Russian standard | 0 | — | 2012 |
| 339 | gost-r-34.10-2001 | gost2001-sign | 13 | legacy | signature | 128-bit | GOST R 34.10-2001 | Withdrawn | 0 | — | 2001 |
| 340 | schnorr | — | 13 | current | signature | 128-bit | — | Classical Schnorr | 0 | — | 1989 |
| 341 | bbs | bbs+ | 13 | current | signature | 128-bit | — | Pairing-based | 0 | — | 2004 |
| 342 | bls12-381-g1 | — | 13 | current | signature | 128-bit | — | Pairing sig | 0 | — | 2018 |
| 343 | bls12-381-g2 | — | 13 | current | signature | 128-bit | — | Pairing sig | 0 | — | 2018 |
| 344 | rainbow | — | 13 | historic | signature | variable | — | Broken 2022 | 0 | — | 2008 |
| 345 | ge-mss | — | 13 | historic | signature | variable | — | — | 0 | — | 2017 |

---

## 13. Post-Quantum Digital Signatures

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 346 | dilithium | ml-dsa | 16 | current | pqc-sig | 128-256-bit | FIPS 204 | NIST standard | 0 | — | 2017 |
| 347 | ml-dsa-44 | dilithium2 | 16 | current | pqc-sig | 128-bit | FIPS 204 | NIST Level 2 | 0 | — | 2024 |
| 348 | ml-dsa-65 | dilithium3 | 16 | current | pqc-sig | 192-bit | FIPS 204 | NIST Level 3 | 0 | — | 2024 |
| 349 | ml-dsa-87 | dilithium5 | 16 | current | pqc-sig | 256-bit | FIPS 204 | NIST Level 5 | 0 | — | 2024 |
| 350 | falcon-512 | — | 16 | current | pqc-sig | 128-bit | FIPS 206 (draft) | NTRU lattice | 0 | — | 2017 |
| 351 | falcon-1024 | — | 16 | current | pqc-sig | 256-bit | FIPS 206 (draft) | NTRU lattice | 0 | — | 2017 |
| 352 | falcon-padded-512 | — | 16 | current | pqc-sig | 128-bit | FIPS 206 (draft) | Padded variant | 0 | — | 2022 |
| 353 | falcon-padded-1024 | — | 16 | current | pqc-sig | 256-bit | FIPS 206 (draft) | Padded variant | 0 | — | 2022 |
| 354 | sphincs+ | slh-dsa | 16 | current | pqc-sig | 128-256-bit | FIPS 205 | Stateless HBS | 0 | — | 2014 |
| 355 | slh-dsa-sha2-128f | — | 16 | current | pqc-sig | 128-bit | FIPS 205 | Fast variant | 0 | — | 2024 |
| 356 | slh-dsa-sha2-128s | — | 16 | current | pqc-sig | 128-bit | FIPS 205 | Small variant | 0 | — | 2024 |
| 357 | slh-dsa-sha2-192f | — | 16 | current | pqc-sig | 192-bit | FIPS 205 | Fast variant | 0 | — | 2024 |
| 358 | slh-dsa-sha2-192s | — | 16 | current | pqc-sig | 192-bit | FIPS 205 | Small variant | 0 | — | 2024 |
| 359 | slh-dsa-sha2-256f | — | 16 | current | pqc-sig | 256-bit | FIPS 205 | Fast variant | 0 | — | 2024 |
| 360 | slh-dsa-sha2-256s | — | 16 | current | pqc-sig | 256-bit | FIPS 205 | Small variant | 0 | — | 2024 |
| 361 | slh-dsa-shake-128f | — | 16 | current | pqc-sig | 128-bit | FIPS 205 | Fast variant | 0 | — | 2024 |
| 362 | slh-dsa-shake-128s | — | 16 | current | pqc-sig | 128-bit | FIPS 205 | Small variant | 0 | — | 2024 |
| 363 | slh-dsa-shake-192f | — | 16 | current | pqc-sig | 192-bit | FIPS 205 | Fast variant | 0 | — | 2024 |
| 364 | slh-dsa-shake-192s | — | 16 | current | pqc-sig | 192-bit | FIPS 205 | Small variant | 0 | — | 2024 |
| 365 | slh-dsa-shake-256f | — | 16 | current | pqc-sig | 256-bit | FIPS 205 | Fast variant | 0 | — | 2024 |
| 366 | slh-dsa-shake-256s | — | 16 | current | pqc-sig | 256-bit | FIPS 205 | Small variant | 0 | — | 2024 |
| 367 | haetae | — | 16 | current | pqc-sig | variable | — | Korean lattice | 0 | — | 2023 |
| 368 | almar | — | 16 | current | pqc-sig | variable | — | Korean lattice | 0 | — | 2023 |

---

## 14. Stateful Hash-Based Signatures

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 369 | lms | — | 17 | current | stateful-sig | 128-256-bit | SP 800-208 | Leighton-Micali | 0 | — | 1994 |
| 370 | hss | — | 17 | current | stateful-sig | 128-256-bit | SP 800-208 | Hierarchical LMS | 0 | — | 2017 |
| 371 | xmss | — | 17 | current | stateful-sig | 128-256-bit | RFC 8391 / SP 800-208 | Merkle sig | 0 | — | 2011 |
| 372 | xmssmt | multi-tree-xmss | 17 | current | stateful-sig | 128-256-bit | RFC 8391 | Multi-tree | 0 | — | 2017 |

---

## 15. Threshold / MPC Cryptography

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 373 | frost | — | 18 | current | threshold | 128-bit | RFC 9591 | Threshold Schnorr | 0 | — | 2020 |
| 374 | tbls | threshold-bls | 18 | current | threshold | 128-bit | — | Threshold BLS | 0 | — | 2018 |
| 375 | gargos | — | 18 | current | threshold | 128-bit | — | Threshold Schnorr | 0 | — | — |
| 376 | tecla | — | 18 | current | threshold | 128-bit | — | 2-party ECDSA | 0 | — | — |
| 377 | the-clash | — | 18 | current | threshold | 128-bit | — | n-party ECDSA | 0 | — | — |
| 378 | classic-schnorr | — | 18 | current | threshold | 128-bit | — | Threshold Schnorr | 0 | — | — |
| 379 | bam | — | 18 | current | threshold | 128-bit | — | 2-party ECDSA | 0 | — | — |
| 380 | ccgmp | — | 18 | current | threshold | 128-bit | — | n-party ECDSA | 0 | — | — |
| 381 | haystack | — | 18 | current | threshold | 128-bit | — | Threshold HBS | 0 | — | — |
| 382 | mithril | — | 18 | current | threshold | 128-bit | — | Threshold ML-DSA | 0 | — | — |
| 383 | quorus | — | 18 | current | threshold | 128-bit | — | Threshold ML-DSA | 0 | — | — |
| 384 | redeta | — | 18 | current | threshold | 128-bit | — | Threshold ECDLP | 0 | — | — |
| 385 | splitkey | — | 18 | current | threshold | 128-bit | — | Server-assisted | 0 | — | — |
| 386 | minimpc | — | 18 | current | threshold | 128-bit | — | Threshold AES+SHA | 0 | — | — |
| 387 | maestro | — | 18 | current | threshold | 128-bit | — | T-AES/T-SHA | 0 | — | — |
| 388 | amber | — | 18 | current | threshold | 128-bit | — | Threshold lattice KEM | 0 | — | — |
| 389 | hermine | — | 18 | current | threshold | 128-bit | — | Threshold lattice sig | 0 | — | — |
| 390 | least | — | 18 | current | threshold | 128-bit | — | Threshold code-based | 0 | — | — |
| 391 | tanuki | — | 18 | current | threshold | 128-bit | — | Threshold lattice sig | 0 | — | — |
| 392 | vinaigrette | — | 18 | current | threshold | 128-bit | — | Threshold UOV+MAYO | 0 | — | — |
| 393 | pantheria | — | 18 | current | threshold | 128-bit | — | RLWE TFHE | 0 | — | — |
| 394 | zama-tfhe | tfhe | 18 | current | threshold | 128-bit | — | Threshold FHE | 0 | — | 2020 |
| 395 | zama-zhenith | — | 18 | current | threshold | 128-bit | — | ZKP component | 0 | — | — |
| 396 | piver | — | 18 | current | threshold | 128-bit | — | VSS | 0 | — | — |
| 397 | schmivitz | — | 18 | current | threshold | 128-bit | — | VOLEith ZKPoK | 0 | — | — |
| 398 | smallwood | — | 18 | current | threshold | 128-bit | — | Hash-based ZKPoK | 0 | — | — |
| 399 | shamir | sss | 18 | current | threshold | 128-bit | — | Secret sharing | 0 | — | 1979 |
| 400 | feldman-vss | — | 18 | current | threshold | 128-bit | — | Verifiable SS | 0 | — | 1987 |
| 401 | pedersen-vss | — | 18 | current | threshold | 128-bit | — | Verifiable SS | 0 | — | 1991 |
| 402 | dkg | — | 18 | current | threshold | 128-bit | — | Distributed KG | 0 | — | 1991 |
| 403 | pvss | — | 18 | current | threshold | 128-bit | — | Publicly verifiable SS | 0 | — | 1999 |
| 404 | ot | — | 18 | current | threshold | 128-bit | — | Oblivious Transfer | 0 | — | 1981 |
| 405 | vole | — | 18 | current | threshold | 128-bit | — | Vector OLE | 0 | — | 2019 |
| 406 | beaver | — | 18 | current | threshold | 128-bit | — | Beaver triples | 0 | — | 1991 |
| 407 | mpc-ecdsa | — | 18 | current | threshold | 128-bit | — | Generic MPC ECDSA | 0 | — | — |
| 408 | mpc-schnorr | — | 18 | current | threshold | 128-bit | — | Generic MPC Schnorr | 0 | — | — |

---

## 16. Lightweight Cryptography

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 409 | ascon-hash256 | — | 19 | current | lightweight | 128-bit | SP 800-232 | NIST LWC hash | 1 | — | 2023 |
| 410 | ascon-xof128 | — | 19 | current | lightweight | 128-bit | SP 800-232 | NIST LWC XOF | 1 | — | 2023 |
| 411 | ascon-cxof128 | — | 19 | current | lightweight | 128-bit | SP 800-232 | Customizable XOF | 1 | — | 2023 |
| 412 | ascon-mac | — | 19 | current | lightweight | 128-bit | SP 800-232 | NIST LWC MAC | 1 | — | 2023 |
| 413 | ascon-prf | — | 19 | current | lightweight | 128-bit | SP 800-232 | NIST LWC PRF | 1 | — | 2023 |
| 414 | photon-beetle-hash | — | 19 | historic | lightweight | 128-bit | NIST LWC | Finalist hash | 1 | — | 2019 |
| 415 | romulus-hash | — | 19 | historic | lightweight | 128-bit | NIST LWC | Finalist hash | 1 | — | 2019 |
| 416 | sparkle-esch | — | 19 | historic | lightweight | 128-bit | NIST LWC | Finalist hash | 1 | — | 2019 |
| 417 | xoodyak-hash | — | 19 | historic | lightweight | 128-bit | NIST LWC | Finalist hash | 1 | — | 2019 |
| 418 | lea | — | 19 | current | lightweight | 128-bit | — | ARX design | 1 | — | 2014 |
| 419 | hight | — | 19 | current | lightweight | 64-bit | — | Korean | 1 | — | 2006 |

---

## 17. DRBG / RNG / Entropy

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 420 | ctr-drbg | — | 20 | current | drbg | 128-256-bit | SP 800-90A | AES-CTR based | 1 | AES-NI | 2007 |
| 421 | hash-drbg | — | 20 | current | drbg | 128-256-bit | SP 800-90A | SHA-based | 1 | SHA-NI | 2007 |
| 422 | hmac-drbg | — | 20 | current | drbg | 128-256-bit | SP 800-90A | HMAC-based | 1 | SHA-NI | 2007 |
| 423 | csprng-system | urandom | 21 | current | rng | — | — | OS abstraction | 1 | RDRAND | — |
| 424 | trng | — | 21 | current | rng | — | — | Hardware entropy | 1 | — | — |
| 425 | entropy-pool | — | 21 | current | rng | — | — | Accumulation | 1 | — | — |
| 426 | reseed-scheduler | — | 21 | current | rng | — | — | Policy/scheduling | 0 | — | — |
| 427 | rdrand | — | 21 | current | rng | 128-bit | — | Intel HW RNG | 1 | RDRAND | 2012 |
| 428 | rdseed | — | 21 | current | rng | 128-bit | — | Intel SEED RNG | 1 | RDSEED | 2014 |
| 429 | jitterentropy | — | 21 | current | rng | — | — | CPU timing jitter | 1 | — | 2015 |
| 430 | haveged | — | 21 | legacy | rng | — | — | HAVAGE entropy | 1 | — | 2003 |
| 431 | fortuna | — | 21 | current | rng | — | — | Ferguson/Schneier | 1 | — | 2003 |
| 432 | yarrow | — | 21 | legacy | rng | — | — | Ferguson/Schneier | 1 | — | 1999 |
| 433 | nist-sp800-90b | — | 21 | current | entropy | — | SP 800-90B | Entropy source | 1 | — | 2018 |
| 434 | nist-sp800-90c | — | 21 | current | rng | — | SP 800-90C | Construction | 1 | — | 2021 |

---

## 18. Zero-Knowledge Proof Systems

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 435 | groth16 | — | 22 | current | zkp | 128-bit | — | SNARK | 0 | — | 2016 |
| 436 | plonk | — | 22 | current | zkp | 128-bit | — | Universal SNARK | 0 | — | 2019 |
| 437 | marlin | — | 22 | current | zkp | 128-bit | — | Universal SNARK | 0 | — | 2019 |
| 438 | halo2 | — | 22 | current | zkp | 128-bit | — | Recursive SNARK | 0 | — | 2020 |
| 439 | plonky2 | — | 22 | current | zkp | 128-bit | — | Recursive SNARK | 0 | — | 2022 |
| 440 | stark | fri-stark | 22 | current | zkp | 128-bit | — | Transparent STARK | 0 | — | 2018 |
| 441 | bulletproofs | — | 22 | current | zkp | 128-bit | — | Inner-product arg | 0 | — | 2017 |
| 442 | spartan | — | 22 | current | zkp | 128-bit | — | SNARK | 0 | — | 2019 |
| 443 | sonic | — | 22 | current | zkp | 128-bit | — | Universal SNARK | 0 | — | 2019 |
| 444 | pinocchio | — | 22 | historic | zkp | 128-bit | — | Early SNARK | 0 | — | 2013 |
| 445 | kzg-commitment | — | 22 | current | zkp | 128-bit | — | Polynomial commit | 0 | — | 2010 |
| 446 | fri | — | 22 | current | zkp | 128-bit | — | IOP of proximity | 0 | — | 2017 |
| 447 | ligero | — | 22 | current | zkp | 128-bit | — | IOP-based | 0 | — | 2017 |
| 448 | dory | — | 22 | current | zkp | 128-bit | — | Inner-product arg | 0 | — | 2020 |
| 449 | supersonic | — | 22 | historic | zkp | 128-bit | — | Transparent SNARK | 0 | — | 2019 |
| 450 | gm17 | — | 22 | current | zkp | 128-bit | — | SNARK variant | 0 | — | 2017 |

---

## 19. Protocol Framework Primitives

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 451 | noise-nn | — | 23 | current | protocol-prim | 128-bit | Noise Framework | No static keys | 0 | — | 2018 |
| 452 | noise-kn | — | 23 | current | protocol-prim | 128-bit | Noise Framework | Initiator known | 0 | — | 2018 |
| 453 | noise-nk | — | 23 | current | protocol-prim | 128-bit | Noise Framework | Responder known | 0 | — | 2018 |
| 454 | noise-kk | — | 23 | current | protocol-prim | 128-bit | Noise Framework | Both known | 0 | — | 2018 |
| 455 | noise-nx | — | 23 | current | protocol-prim | 128-bit | Noise Framework | Initiator transmitted | 0 | — | 2018 |
| 456 | noise-xn | — | 23 | current | protocol-prim | 128-bit | Noise Framework | Responder transmitted | 0 | — | 2018 |
| 457 | noise-xk | — | 23 | current | protocol-prim | 128-bit | Noise Framework | — | 0 | — | 2018 |
| 458 | noise-kx | — | 23 | current | protocol-prim | 128-bit | Noise Framework | — | 0 | — | 2018 |
| 459 | noise-in | — | 23 | current | protocol-prim | 128-bit | Noise Framework | Initiator immediate | 0 | — | 2018 |
| 460 | noise-ik | — | 23 | current | protocol-prim | 128-bit | Noise Framework | — | 0 | — | 2018 |
| 461 | noise-ix | — | 23 | current | protocol-prim | 128-bit | Noise Framework | — | 0 | — | 2018 |
| 462 | noise-xx | — | 23 | current | protocol-prim | 128-bit | Noise Framework | Mutual auth | 0 | — | 2018 |
| 463 | noise-ikpsk2 | — | 23 | current | protocol-prim | 128-bit | Noise Framework | WireGuard | 0 | — | 2018 |
| 464 | signal-x3dh | — | 23 | current | protocol-prim | 128-bit | Signal Spec | Initial handshake | 0 | — | 2016 |
| 465 | signal-double-ratchet | — | 23 | current | protocol-prim | 128-bit | Signal Spec | Key rotation | 0 | — | 2016 |
| 466 | opaque | — | 23 | current | protocol-prim | 128-bit | RFC 9496 | PAKE | 0 | — | 2023 |
| 467 | spake2 | — | 23 | current | protocol-prim | 128-bit | RFC 9383 | PAKE | 0 | — | 2023 |
| 468 | spake2+ | — | 23 | current | protocol-prim | 128-bit | RFC 9383 | Augmented PAKE | 0 | — | 2023 |
| 469 | srp | — | 23 | legacy | protocol-prim | variable | RFC 2945 | PAKE | 0 | — | 1998 |
| 470 | j-pake | — | 23 | legacy | protocol-prim | 128-bit | RFC 8236 | PAKE | 0 | — | 2015 |
| 471 | dragonfly | — | 23 | current | protocol-prim | 128-bit | RFC 7664 | WPA3 / EAP-pwd | 0 | — | 2015 |
| 472 | otr | — | 23 | legacy | protocol-prim | 128-bit | — | Off-the-Record | 0 | — | 2004 |
| 473 | otrv4 | — | 23 | planned | protocol-prim | 128-bit | — | OTR next-gen | 0 | — | 2022 |
| 474 | mtproto | — | 23 | current | protocol-prim | 128-bit | — | Telegram | 0 | — | 2013 |
| 475 | wireguard | — | 23 | current | protocol-prim | 128-bit | — | Noise_IKpsk2 | 0 | — | 2018 |

---

## 20. PKI / Certificate / Encoding Utilities

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 476 | x509v3 | — | 24 | current | pki-util | — | RFC 5280 | Certificate format | 0 | — | 1996 |
| 477 | x509v1 | — | 24 | legacy | pki-util | — | RFC 1422 | Legacy cert | 0 | — | 1993 |
| 478 | crl | — | 24 | current | pki-util | — | RFC 5280 | Revocation list | 0 | — | 1996 |
| 479 | ocsp | — | 24 | current | pki-util | — | RFC 6960 | Online status | 0 | — | 1999 |
| 480 | ocsp-stapling | — | 24 | current | pki-util | — | RFC 6066 | TLS extension | 0 | — | 2011 |
| 481 | csr | pkcs10 | 24 | current | pki-util | — | RFC 2986 | Cert request | 0 | — | 2000 |
| 482 | cms | pkcs7 | 24 | current | pki-util | — | RFC 5652 | Cryptographic msg | 0 | — | 2004 |
| 483 | scep | — | 24 | current | pki-util | — | RFC 8894 | Enrollment | 0 | — | 2020 |
| 484 | est | — | 24 | current | pki-util | — | RFC 7030 | Enrollment | 0 | — | 2013 |
| 485 | acme | — | 24 | current | pki-util | — | RFC 8555 | Let's Encrypt | 0 | — | 2019 |
| 486 | ct | certificate-transparency | 24 | current | pki-util | — | RFC 9162 | Signed cert logs | 0 | — | 2022 |
| 487 | mft | manifest | 24 | current | pki-util | — | RFC 6486 | RPKI manifest | 0 | — | 2012 |
| 488 | roa | — | 24 | current | pki-util | — | RFC 6482 | RPKI attestation | 0 | — | 2012 |
| 489 | tal | — | 24 | current | pki-util | — | RFC 7730 | Trust anchor | 0 | — | 2016 |
| 490 | rfc822name | — | 24 | current | pki-util | — | RFC 5280 | SAN type | 0 | — | — |
| 491 | ipaddress | — | 24 | current | pki-util | — | RFC 5280 | SAN type | 0 | — | — |
| 492 | subjectaltname | san | 24 | current | pki-util | — | RFC 5280 | Extension | 0 | — | — |
| 493 | authoritykeyid | aki | 24 | current | pki-util | — | RFC 5280 | Extension | 0 | — | — |
| 494 | subjectkeyid | ski | 24 | current | pki-util | — | RFC 5280 | Extension | 0 | — | — |
| 495 | keyusage | — | 24 | current | pki-util | — | RFC 5280 | Extension | 0 | — | — |
| 496 | extendedkeyusage | eku | 24 | current | pki-util | — | RFC 5280 | Extension | 0 | — | — |
| 497 | basicconstraints | — | 24 | current | pki-util | — | RFC 5280 | Extension | 0 | — | — |
| 498 | nameconstraints | — | 24 | current | pki-util | — | RFC 5280 | Extension | 0 | — | — |
| 499 | cdp | crldp | 24 | current | pki-util | — | RFC 5280 | Extension | 0 | — | — |
| 500 | aia | — | 24 | current | pki-util | — | RFC 5280 | Extension | 0 | — | — |
| 501 | ocsp-nocheck | — | 24 | current | pki-util | — | RFC 6960 | Extension | 0 | — | — |
| 502 | precert-poison | — | 24 | current | pki-util | — | RFC 6962 | CT extension | 0 | — | — |
| 503 | sct | — | 24 | current | pki-util | — | RFC 6962 | CT extension | 0 | — | — |
| 504 | tls-features | — | 24 | current | pki-util | — | RFC 7633 | Extension | 0 | — | — |
| 505 | signed-timestamp | — | 24 | current | pki-util | — | RFC 3161 | TSP | 0 | — | 2001 |
| 506 | tsp | rfc3161 | 24 | current | pki-util | — | RFC 3161 | Timestamp | 0 | — | 2001 |
| 507 | cades | — | 24 | current | pki-util | — | ETSI TS 101 733 | CMS advanced | 0 | — | 2000 |
| 508 | pades | — | 24 | current | pki-util | — | ETSI TS 102 778 | PDF signing | 0 | — | 2009 |
| 509 | xades | — | 24 | current | pki-util | — | ETSI TS 101 903 | XML signing | 0 | — | 2002 |
| 510 | asn1-der | — | 24 | current | pki-util | — | ITU-T X.690 | Encoding | 0 | — | 1988 |
| 511 | asn1-ber | — | 24 | legacy | pki-util | — | ITU-T X.690 | Encoding | 0 | — | 1988 |
| 512 | asn1-cer | — | 24 | current | pki-util | — | ITU-T X.690 | Encoding | 0 | — | 1988 |
| 513 | asn1-per | — | 24 | current | pki-util | — | ITU-T X.691 | Encoding | 0 | — | 2002 |
| 514 | asn1-oer | — | 24 | current | pki-util | — | ITU-T X.696 | Encoding | 0 | — | 2015 |
| 515 | asn1-xer | — | 24 | current | pki-util | — | ITU-T X.693 | XML encoding | 0 | — | 2001 |

---

## 21. Hardware Security / HSM / TEE Interfaces

| # | algo_name | algo_alias | category_fk | status | type | security_level | standard | note | streaming | hw_accel | year |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 516 | pkcs11 | cryptoki | 25 | current | hw-interface | — | RSA PKCS#11 | HSM API | 0 | — | 1994 |
| 517 | pkcs11-3.0 | — | 25 | current | hw-interface | — | PKCS#11 v3.0 | Latest revision | 0 | — | 2020 |
| 518 | capi | cryptoapi | 25 | legacy | hw-interface | — | Microsoft | Windows legacy | 0 | — | 1996 |
| 519 | cng | — | 25 | current | hw-interface | — | Microsoft | Windows next-gen | 0 | — | 2007 |
| 520 | tpm1.2 | — | 25 | legacy | hw-interface | — | TCG | Trusted Platform | 0 | — | 2003 |
| 521 | tpm2.0 | — | 25 | current | hw-interface | — | TCG | Trusted Platform | 0 | — | 2014 |
| 522 | intel-sgx | sgx | 25 | current | hw-interface | — | Intel | Enclave | 0 | — | 2015 |
| 523 | intel-tdx | tdx | 25 | planned | hw-interface | — | Intel | VM TEE | 0 | — | 2021 |
| 524 | amd-sev | sev | 25 | current | hw-interface | — | AMD | VM encryption | 0 | — | 2016 |
| 525 | amd-sev-snp | snp | 25 | current | hw-interface | — | AMD | Secure nested paging | 0 | — | 2020 |
| 526 | arm-trustzone | trustzone | 25 | current | hw-interface | — | ARM | Secure world | 0 | — | 2004 |
| 527 | arm-cca | cca | 25 | planned | hw-interface | — | ARM | Confidential compute | 0 | — | 2021 |
| 528 | apple-secure-enclave | sep | 25 | current | hw-interface | — | Apple | A-series/M-series | 0 | — | 2013 |
| 529 | nitro-enclaves | — | 25 | current | hw-interface | — | AWS | Cloud TEE | 0 | — | 2019 |
| 530 | nvidia-cc | — | 25 | planned | hw-interface | — | NVIDIA | GPU TEE | 0 | — | 2023 |
| 531 | java-jce | — | 25 | current | hw-interface | — | Oracle | Java crypto | 0 | — | 1997 |
| 532 | openssl-engine | — | 25 | legacy | hw-interface | — | OpenSSL | ENGINE API | 0 | — | 2000 |
| 533 | openssl-provider | — | 25 | current | hw-interface | — | OpenSSL 3.x | Provider API | 0 | — | 2021 |
| 534 | wolfssl-fips | — | 25 | current | hw-interface | — | wolfSSL | FIPS module | 0 | — | — |
| 535 | botan-p11 | — | 25 | current | hw-interface | — | Botan | PKCS#11 wrapper | 0 | — | — |
| 536 | libp11 | — | 25 | current | hw-interface | — | OpenSC | PKCS#11 engine | 0 | — | — |
| 537 | opencryptoki | — | 25 | current | hw-interface | — | IBM | PKCS#11 impl | 0 | — | — |
| 538 | softhsm2 | — | 25 | current | hw-interface | — | OpenDNSSEC | Soft HSM | 0 | — | 2014 |

---

## 22. Cryptographic Libraries / Frameworks / Toolkits

| lib_id | lib_name | lang | license | fips_cert | provider_arch | tls_stack | asn1_engine | cert_engine | hsm_support | secure_mem | rng_pipeline | pqc_ready | latest_stable |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | OpenSSL | C | Apache-2.0 | 4985 | Provider (3.x) | 1 | 1 | 1 | PKCS#11,ENGINE | 1 | RAND_DRBG,EVP_RAND | 1 | 3.5.0 |
| 2 | BoringSSL | C | OpenSSL+ISC | — | SSL_PRIVATE / BORINGSSL | 1 | 1 | 1 | — | 1 | RAND_bytes | 1 | 2025-Q1 |
| 3 | LibreSSL | C | ISC / OpenSSL | — | LibreSSL API | 1 | 1 | 1 | — | 1 | arc4random | 0 | 4.0.0 |
| 4 | wolfSSL | C | GPL-2.0+ | 3389 | wolfCrypt | 1 | 1 | 1 | PKCS#11,TPM2.0 | 1 | wc_RNG | 1 | 5.7.4 |
| 5 | mbed TLS | C | Apache-2.0 | — | PSA Crypto API | 1 | 1 | 1 | PSA SE driver | 1 | mbedtls_ctr_drbg | 1 | 3.6.2 |
| 6 | GnuTLS | C | LGPL-2.1+ | — | GnuTLS internal | 1 | 1 | 1 | PKCS#11 | 1 | gnutls_rnd | 1 | 3.8.4 |
| 7 | NSS | C/C++ | MPL-2.0 | — | NSS softoken | 1 | 1 | 1 | PKCS#11 | 1 | PK11_Random | 0 | 3.98 |
| 8 | libsodium | C | ISC | — | High-level API | 0 | 0 | 0 | — | 1 | randombytes | 0 | 1.0.20 |
| 9 | Botan | C++ | BSD-2 | — | Provider (modular) | 1 | 1 | 1 | PKCS#11,TPM | 1 | System_RNG | 1 | 3.6.0 |
| 10 | Crypto++ | C++ | Boost/BSL | — | Crypto++ filters | 0 | 1 | 0 | — | 0 | OS_RNG | 0 | 8.9.0 |
| 11 | BouncyCastle | Java/C# | MIT | — | JCE Provider | 0 | 1 | 1 | PKCS#11 | 0 | SecureRandom | 1 | 1.79 |
| 12 | Conscrypt | Java | Apache-2.0 | — | BoringSSL binding | 1 | 1 | 1 | — | 1 | BoringSSL RAND | 0 | 2.5.2 |
| 13 | ring | Rust | ISC | — | ring::aead | 0 | 0 | 0 | — | 1 | SystemRandom | 0 | 0.17.8 |
| 14 | rustls | Rust | Apache-2.0/ISC | — | rustls::crypto | 1 | 0 | 1 | — | 1 | getrandom | 0 | 0.23.0 |
| 15 | aws-lc | C | Apache-2.0 | — | AWS-LC API | 1 | 1 | 1 | — | 1 | RAND_bytes | 1 | 1.39.0 |
| 16 | liboqs | C | MIT | — | OQS_PROVIDER | 0 | 0 | 0 | — | 0 | OQS_random | 1 | 0.12.0 |
| 17 | pqcrypto | Rust | MIT/Apache | — | Rust wrappers | 0 | 0 | 0 | — | 0 | osrng | 1 | 0.5.0 |
| 18 | Go crypto | Go | BSD-3 | — | standard library | 1 | 1 | 1 | — | 0 | crypto/rand | 0 | 1.24 |
| 19 | Python cryptography | Python/Rust | Apache-2.0 | — | hazmat + OpenSSL | 0 | 1 | 1 | PKCS#11 | 0 | os.urandom | 1 | 44.0 |
| 20 | PyCryptodome | Python | BSD-2 | — | Pure Py + C | 0 | 0 | 0 | — | 0 | os.urandom | 0 | 3.21 |
| 21 | tweetnacl | C | Public domain | — | NaCl compat | 0 | 0 | 0 | — | 0 | randombytes | 0 | 20140427 |
| 22 | NaCl | C | Public domain | — | NaCl API | 0 | 0 | 0 | — | 0 | randombytes | 0 | 20110221 |
| 23 | libgcrypt | C | LGPL-2.1+ | — | Libgcrypt sexp | 0 | 1 | 0 | — | 0 | gcry_random | 0 | 1.11.0 |
| 24 | Nettle | C | LGPL-3+ | — | Nettle low-level | 0 | 0 | 0 | — | 0 | yarrow | 0 | 3.10 |
| 25 | libtomcrypt | C | Public domain | — | LTC descriptors | 0 | 0 | 0 | — | 0 | rng_get_bytes | 0 | 1.18.2 |
| 26 | BearSSL | C | MIT | — | BearSSL engine | 1 | 1 | 1 | — | 0 | br_ssl_engine | 0 | 0.6 |
| 27 | s2n-tls | C | Apache-2.0 | — | s2n crypto | 1 | 1 | 1 | — | 1 | s2n_rand | 0 | 1.5.0 |
| 28 | MatrixSSL | C | GPL/Commercial | — | MatrixSSL crypto | 1 | 1 | 1 | PKCS#11 | 0 | psGetEntropy | 0 | 4.6.0 |
| 29 | SecureBlackbox | .NET/Java | Commercial | — | SB crypto | 0 | 1 | 1 | PKCS#11,CAPI | 0 | PRNG | 0 | 16.0 |
| 30 | Tink | Java/Go/C++ | Apache-2.0 | — | Tink primitives | 0 | 1 | 1 | — | 1 | Tink RNG | 0 | 1.15 |
| 31 | monocypher | C | CC0-1.0 | — | Monocypher API | 0 | 0 | 0 | — | 1 | crypto_random | 0 | 4.0.2 |
| 32 | libhydrogen | C | ISC | — | Hydrogen API | 0 | 0 | 0 | — | 1 | randombytes | 0 | 1.0.1 |
| 33 | evercrypt | F*→C | Apache-2.0 | — | HACL* / Vale | 0 | 0 | 0 | — | 1 | EverCrypt DRBG | 0 | 0.0.1 |
| 34 | hacl-star | F*→C | Apache-2.0 | — | HACL* API | 0 | 0 | 0 | — | 1 | HACL Random | 0 | 0.0.1 |
| 35 | zig-crypto | Zig | MIT | — | std.crypto | 0 | 0 | 0 | — | 0 | std.crypto.random | 0 | 0.14 |
| 36 | blst | C/ASM | Apache-2.0 | — | BLS12-381 | 0 | 0 | 0 | — | 0 | — | 0 | 0.3.11 |
| 37 | mcl | C++ | BSD-3 | — | BLS / pairing | 0 | 0 | 0 | — | 0 | — | 0 | 1.93 |
| 38 | relic | C | LGPL-2.1 | — | Pairing-based | 0 | 0 | 0 | — | 0 | — | 0 | 0.6.0 |
| 39 | miracl-core | C/C++ | AGPL/Commercial | — | MIRACL | 0 | 0 | 0 | — | 0 | — | 0 | 2.0 |
| 40 | secp256k1 | C | MIT | — | Bitcoin lib | 0 | 0 | 0 | — | 0 | — | 0 | 0.6.0 |

---

## 23. Algorithm ↔ Library Cross-Reference (Selected High-Value Mappings)

| map_id | algo_name | lib_name | api_surface | hw_accel | status |
| ---: | --- | --- | --- | --- | --- |
| 1 | aes-256-gcm | OpenSSL | EVP_aes_256_gcm() | AES-NI+PCLMUL | full |
| 2 | aes-256-gcm | BoringSSL | EVP_aead_aes_256_gcm() | AES-NI+PCLMUL | full |
| 3 | aes-256-gcm | wolfSSL | wc_AesGcmEncrypt() | AES-NI+PCLMUL | full |
| 4 | aes-256-gcm | mbed TLS | mbedtls_gcm_setkey() | AES-NI | full |
| 5 | aes-256-gcm | libsodium | crypto_aead_aes256gcm_* | AES-NI+PCLMUL | full |
| 6 | chacha20-poly1305 | OpenSSL | EVP_chacha20_poly1305() | AVX2 | full |
| 7 | chacha20-poly1305 | BoringSSL | EVP_aead_chacha20_poly1305() | AVX2 | full |
| 8 | chacha20-poly1305 | libsodium | crypto_aead_chacha20poly1305_* | AVX2 | full |
| 9 | chacha20-poly1305 | wolfSSL | wc_ChaCha20Poly1305_* | AVX2 | full |
| 10 | x25519 | OpenSSL | EVP_PKEY_X25519 | — | full |
| 11 | x25519 | BoringSSL | X25519() | — | full |
| 12 | x25519 | libsodium | crypto_scalarmult_curve25519() | — | full |
| 13 | x25519 | mbed TLS | mbedtls_ecp_group_load(25519) | — | full |
| 14 | ed25519 | OpenSSL | EVP_PKEY_ED25519 | — | full |
| 15 | ed25519 | BoringSSL | ED25519_sign() | — | full |
| 16 | ed25519 | libsodium | crypto_sign_ed25519_* | — | full |
| 17 | ed25519 | wolfSSL | wc_ed25519_sign_msg() | — | full |
| 18 | sha256 | OpenSSL | EVP_sha256() | SHA-NI | full |
| 19 | sha256 | BoringSSL | EVP_sha256() | SHA-NI | full |
| 20 | sha256 | libsodium | crypto_hash_sha256() | — | full |
| 21 | sha3-256 | OpenSSL | EVP_sha3_256() | — | full |
| 22 | blake2b | OpenSSL | EVP_blake2b512() | AVX2 | full |
| 23 | blake2b | libsodium | crypto_generichash() | AVX2 | full |
| 24 | blake3 | OpenSSL | — | AVX2 | planned |
| 25 | blake3 | BoringSSL | — | AVX2 | planned |
| 26 | ml-kem-768 | OpenSSL | EVP_PKEY_ML_KEM_768 | — | full (3.5) |
| 27 | ml-kem-768 | BoringSSL | KYBER768 | — | full |
| 28 | ml-kem-768 | wolfSSL | wc_MlKemKey_Init(768) | — | full |
| 29 | ml-dsa-65 | OpenSSL | EVP_PKEY_ML_DSA_65 | — | full (3.5) |
| 30 | ml-dsa-65 | BoringSSL | DILITHIUM3 | — | full |
| 31 | ml-dsa-65 | wolfSSL | wc_MlDsaKey_Init(65) | — | full |
| 32 | hkdf | OpenSSL | EVP_KDF_HKDF() | — | full |
| 33 | hkdf | BoringSSL | HKDF() | — | full |
| 34 | hkdf | libsodium | crypto_kdf_derive_from_key() | — | full |
| 35 | argon2id | OpenSSL | EVP_KDF_argon2id() | — | full (3.2+) |
| 36 | argon2id | libsodium | crypto_pwhash_argon2id() | — | full |
| 37 | argon2id | Botan | Argon2id | — | full |
| 38 | rsa-pss | OpenSSL | EVP_PKEY_RSA_PSS | — | full |
| 39 | rsa-pss | BoringSSL | RSA_sign_pss_mgf1 | — | full |
| 40 | ecdsa | OpenSSL | EVP_DigestSign() | — | full |
| 41 | ecdsa | BoringSSL | ECDSA_sign() | — | full |
| 42 | ecdsa | wolfSSL | wc_ecc_sign_hash() | — | full |
| 43 | ctr-drbg | OpenSSL | EVP_RAND_ctr_DRBG() | AES-NI | full |
| 44 | ctr-drbg | mbed TLS | mbedtls_ctr_drbg_random() | AES-NI | full |
| 45 | ctr-drbg | wolfSSL | wc_RNG_GenerateBlock() | AES-NI | full |
| 46 | pkcs11 | OpenSSL | pkcs11-provider | — | full |
| 47 | pkcs11 | Botan | PKCS11_Module | — | full |
| 48 | pkcs11 | wolfSSL | wolfSSL_PKCS11_* | — | full |
| 49 | tpm2.0 | wolfSSL | wolfTPM2_* | — | full |
| 50 | tpm2.0 | OpenSSL | tpm2-provider | — | partial |

---

## 24. Protocol Integration Reference

| proto_id | proto_name | algo_name | role | rfc_std |
| ---: | --- | --- | --- | --- |
| 1 | TLS 1.2 | aes-256-gcm | cipher-suite | RFC 5289 |
| 2 | TLS 1.2 | aes-128-gcm | cipher-suite | RFC 5289 |
| 3 | TLS 1.2 | aes-256-cbc | cipher-suite | RFC 3268 |
| 4 | TLS 1.2 | hmac-sha256 | PRF / MAC | RFC 5246 |
| 5 | TLS 1.2 | ecdhe-rsa | key-exchange | RFC 4492 |
| 6 | TLS 1.2 | ecdhe-ecdsa | key-exchange | RFC 4492 |
| 7 | TLS 1.2 | rsa | authentication | RFC 5246 |
| 8 | TLS 1.3 | aes-256-gcm | cipher-suite | RFC 8446 |
| 9 | TLS 1.3 | aes-128-gcm | cipher-suite | RFC 8446 |
| 10 | TLS 1.3 | chacha20-poly1305 | cipher-suite | RFC 8446 |
| 11 | TLS 1.3 | aes-128-ccm | cipher-suite | RFC 8446 |
| 12 | TLS 1.3 | hkdf | key-schedule | RFC 8446 |
| 13 | TLS 1.3 | x25519 | key-exchange | RFC 8446 |
| 14 | TLS 1.3 | secp256r1 | key-exchange | RFC 8446 |
| 15 | TLS 1.3 | ed25519 | signature-alg | RFC 8446 |
| 16 | TLS 1.3 | rsa-pss | signature-alg | RFC 8446 |
| 17 | TLS 1.3 | ml-kem-768 | key-exchange | RFC 9591 (draft) |
| 18 | TLS 1.3 | ml-dsa-65 | signature-alg | RFC 9591 (draft) |
| 19 | SSH | aes-256-gcm | encryption | RFC 5647 |
| 20 | SSH | chacha20-poly1305 | encryption | RFC 9346 |
| 21 | SSH | curve25519-sha256 | kex | RFC 8731 |
| 22 | SSH | ecdh-sha2-nistp256 | kex | RFC 5656 |
| 23 | SSH | rsa-sha2-256 | hostkey | RFC 8332 |
| 24 | SSH | ed25519 | hostkey | RFC 8709 |
| 25 | IPsec | aes-256-gcm | encryption | RFC 4106 |
| 26 | IPsec | aes-256-cbc | encryption | RFC 3602 |
| 27 | IPsec | hmac-sha256 | integrity | RFC 4868 |
| 28 | IPsec | ecdh | IKE | RFC 5903 |
| 29 | Noise | chacha20-poly1305 | cipher | Noise Framework |
| 30 | Noise | aes-256-gcm | cipher | Noise Framework |
| 31 | Noise | x25519 | dh | Noise Framework |
| 32 | Noise | blake2s | hash | Noise Framework |
| 33 | Noise | sha256 | hash | Noise Framework |
| 34 | Signal | x3dh | initial-handshake | Signal Spec |
| 35 | Signal | double-ratchet | key-rotation | Signal Spec |
| 36 | Signal | x25519 | dh | Signal Spec |
| 37 | Signal | aes-256-cbc | encryption | Signal Spec |
| 38 | Signal | hmac-sha256 | mac | Signal Spec |
| 39 | WireGuard | chacha20-poly1305 | encryption | WireGuard |
| 40 | WireGuard | x25519 | dh | WireGuard |
| 41 | WireGuard | blake2s | hash | WireGuard |
| 42 | WireGuard | poly1305 | mac | WireGuard |
| 43 | SRTP | aes-256-gcm | encryption | RFC 7714 |
| 44 | SRTP | aes-128-ctr | encryption | RFC 3711 |
| 45 | SRTP | hmac-sha1 | integrity | RFC 3711 |
| 46 | DNSSEC | rsa-sha256 | signature | RFC 5702 |
| 47 | DNSSEC | ecdsa-p256-sha256 | signature | RFC 6605 |
| 48 | DNSSEC | ed25519 | signature | RFC 8080 |
| 49 | JOSE | aes-256-gcm | JWE enc | RFC 7518 |
| 50 | JOSE | rsa-oaep | JWE alg | RFC 7518 |
| 51 | JOSE | ecdh-es | JWE alg | RFC 7518 |
| 52 | JOSE | hs256 | JWS alg | RFC 7518 |
| 53 | JOSE | es256 | JWS alg | RFC 7518 |
| 54 | JOSE | eddsa | JWS alg | RFC 8037 |
| 55 | JOSE | pbkdf2 | JWE pbes | RFC 7518 |
| 56 | COSE | aes-256-gcm | encryption | RFC 8152 |
| 57 | COSE | chacha20-poly1305 | encryption | RFC 8152 |
| 58 | COSE | eddsa | signature | RFC 8152 |
| 59 | COSE | es256 | signature | RFC 8152 |
| 60 | S/MIME | aes-256-gcm | encryption | RFC 8551 |
| 61 | S/MIME | rsa-oaep | key-transport | RFC 8551 |
| 62 | S/MIME | ecdsa-sha256 | signature | RFC 8551 |
| 63 | OpenPGP | aes-256 | symmetric | RFC 4880bis |
| 64 | OpenPGP | camellia-256 | symmetric | RFC 5581 |
| 65 | OpenPGP | sha256 | hash | RFC 4880bis |
| 66 | OpenPGP | sha3-256 | hash | RFC 9580 |
| 67 | OpenPGP | ed25519 | signature | RFC 9580 |
| 68 | OpenPGP | x25519 | encryption | RFC 9580 |
| 69 | MACsec | aes-256-gcm | encryption | IEEE 802.1AE |
| 70 | MACsec | aes-xpn | encryption | IEEE 802.1AEbw |
| 71 | 5G-NAS | aes-256 | encryption | 3GPP TS 33.501 |
| 72 | 5G-NAS | snow3g | encryption | 3GPP TS 33.501 |
| 73 | 5G-NAS | zuc | encryption | 3GPP TS 33.501 |
| 74 | 5G-NAS | hmac-sha256 | integrity | 3GPP TS 33.501 |
| 75 | WPA3 | aes-128-ccmp | encryption | IEEE 802.11 |
| 76 | WPA3 | aes-256-gcmp | encryption | IEEE 802.11 |
| 77 | WPA3 | hmac-sha384 | integrity | IEEE 802.11 |
| 78 | WPA3 | dragonfly | key-exchange | RFC 7664 |
| 79 | QUIC | aes-128-gcm | cipher-suite | RFC 9001 |
| 80 | QUIC | aes-256-gcm | cipher-suite | RFC 9001 |
| 81 | QUIC | chacha20-poly1305 | cipher-suite | RFC 9001 |
| 82 | QUIC | hkdf | key-derivation | RFC 9001 |
| 83 | OAuth2 | hs256 | JWS/JWT | RFC 7515 |
| 84 | OAuth2 | rs256 | JWS/JWT | RFC 7515 |
| 85 | OAuth2 | es256 | JWS/JWT | RFC 7515 |
| 86 | OAuth2 | eddsa | JWS/JWT | RFC 8037 |
| 87 | FIDO2/U2F | ecdsa-p256 | attestation | FIDO Spec |
| 88 | FIDO2 | ed25519 | attestation | FIDO Spec |
| 89 | FIDO2 | hmac-secret | extension | FIDO Spec |
| 90 | Ethereum | keccak256 | hash | Yellow Paper |
| 91 | Ethereum | secp256k1 | signature | Yellow Paper |
| 92 | Bitcoin | sha256 | hash | Bitcoin |
| 93 | Bitcoin | ripemd160 | hash | Bitcoin |
| 94 | Bitcoin | secp256k1 | signature | Bitcoin |
| 95 | Bitcoin | schnorr | signature | BIP-0340 |
| 96 | Bitcoin | taproot | address | BIP-0341 |
| 97 | Tor | x25519 | onion-key | Tor Spec |
| 98 | Tor | ed25519 | identity | Tor Spec |
| 99 | Tor | ntor | handshake | Tor Spec |
| 100 | ZCash | groth16 | shielded-proof | ZCash Protocol |
| 101 | ZCash | bls12-381 | signature | ZCash Protocol |
| 102 | Filecoin | bls12-381 | signature | Filecoin Spec |
| 103 | Ethereum2 | bls12-381 | signature | Ethereum Spec |
| 104 | Diem/Libra | ed25519 | signature | Diem Spec |
| 105 | Tendermint | ed25519 | consensus | Tendermint Spec |
| 106 | Noise-NN | chacha20-poly1305 | cipher | Noise |
| 107 | Noise-NN | x25519 | dh | Noise |
| 108 | Noise-NN | blake2s | hash | Noise |

---

## Inventory Totals by Category

| cat_id | Category | Count |
| ---: | --- | ---: |
| 1 | encoding | 21 |
| 2 | checksum | 13 |
| 3 | hash | 65 |
| 4 | xof | 14 |
| 5 | pw-kdf | 19 |
| 6 | block-cipher | 43 |
| 7 | stream-cipher | 26 |
| 8 | block-mode | 11 |
| 9 | aead | 38 |
| 10 | mac | 26 |
| 11 | kdf | 23 |
| 12 | key-agree | 18 |
| 13 | signature | 18 |
| 14 | pke | 3 |
| 15 | pqc-kem | 28 |
| 16 | pqc-sig | 23 |
| 17 | stateful-sig | 4 |
| 18 | threshold | 36 |
| 19 | lightweight | 11 |
| 20 | drbg | 3 |
| 21 | rng | 11 |
| 22 | zkp | 16 |
| 23 | protocol-prim | 25 |
| 24 | pki-util | 40 |
| 25 | hw-interface | 23 |
| — | **Grand Total Algorithms** | **538** |
| — | **Libraries Catalogued** | **40** |
| — | **Protocol Integrations** | **108** |

---

## Notes & Aliases Index

**Hash aliases:**
- `nthash` → `nt`
- `sha512/224` → `sha512-224`
- `sha512/256` → `sha512-256`
- `gost2012-256` → `streebog256`
- `gost2012-512` → `streebog512`
- `gost94` → `gost-r-34.11-94`

**Cipher aliases:**
- `rijndael-128/192/256` → `aes-128/192/256`
- `tdes`, `dea-3` → `3des`
- `dea-1` → `des`
- `sms4` → `sm4`
- `grasshopper` → `kuznyechik`
- `gost89` → `magma`

**KEM aliases:**
- `kyber` → `ml-kem`
- `kyber512` → `ml-kem-512`
- `kyber768` → `ml-kem-768`
- `kyber1024` → `ml-kem-1024`
- `dilithium` → `ml-dsa`
- `dilithium2` → `ml-dsa-44`
- `dilithium3` → `ml-dsa-65`
- `dilithium5` → `ml-dsa-87`
- `slh-dsa` → `sphincs+`

**Key agreement aliases:**
- `curve25519` → `x25519`
- `curve448` → `x448`
- `diffie-hellman` → `dh`

**Encoding aliases:**
- `hex` → `base16`
- `pfx` → `pkcs12`

---

## Implementation Language Index (Library)

| Language | Libraries |
| --- | --- |
| C | OpenSSL, BoringSSL, LibreSSL, wolfSSL, mbed TLS, GnuTLS, NSS, libsodium, Botan, libgcrypt, Nettle, libtomcrypt, BearSSL, s2n-tls, MatrixSSL, tweetnacl, NaCl, monocypher, libhydrogen, aws-lc, liboqs, secp256k1, blst, relic, evercrypt, hacl-star |
| C++ | Botan, Crypto++, mcl, miracl-core, SecureBlackbox |
| Java | BouncyCastle, Conscrypt, Tink, SecureBlackbox |
| C# | BouncyCastle, SecureBlackbox |
| Rust | ring, rustls, pqcrypto, evercrypt, hacl-star |
| Go | Go crypto, s2n-tls (partial), Tink |
| Python | Python cryptography, PyCryptodome, Tink |
| Zig | zig-crypto |
| F* | evercrypt, hacl-star |

---

## Hardware Acceleration Index

| Instruction / Coprocessor | Algorithms Supported |
| --- | --- |
| AES-NI | AES-128/192/256, AES-GCM, AES-CCM, AES-XTS, AES-KW, AES-KWP, AES-SIV, AES-OCB, AES-EAX, AES-GMAC, AES-XPN, CTR-DRBG, Camellia, ARIA |
| PCLMULQDQ | AES-GCM, AES-GCM-SIV, AES-GMAC, AES-XPN, GHASH |
| SHA-NI | SHA-224/256/384/512, SHA-512/224, SHA-512/256, SHA1, HMAC-SHA*, HASH-DRBG, HMAC-DRBG |
| AVX2 / AVX-512 | BLAKE2b/s/bp/sp, BLAKE3, ChaCha20, XChaCha20, Poly1305, KangarooTwelve, XXH3, Argon2, Scrypt |
| RDRAND / RDSEED | CSPRNG-system, TRNG abstraction |
| ARMv8 Crypto | AES, SHA-1, SHA-256, Poly1305, ChaCha20 |
| ARM NEON | BLAKE2, ChaCha20, Poly1305 |
| VIA PadLock | AES, SHA-256, RNG |
| POWER8 / POWER9 | AES, SHA-256, SHA-512 |
| S390 CPACF | AES, SHA-256, SHA-512, GHASH, ChaCha20, Poly1305 |
| Intel QAT | RSA, ECDSA, AES-GCM, compression |
| NVIDIA GPU | AES, RSA, ECC (cuCrypt), ML-DSA (planned) |

---

## Streaming Support Index

| Streaming-Capable Category | Examples |
| --- | --- |
| Hash / XOF | All SHA-2, SHA-3, BLAKE2, BLAKE3, Skein, KangarooTwelve, SM3, Streebog, RIPEMD, MD5, Whirlpool, Tiger |
| Stream Ciphers | ChaCha20, Salsa20, XSalsa20, XChaCha20, RC4, HC-128/256, Rabbit, SOSEMANUK, Grain, ZUC, SNOW3G |
| MAC | HMAC, KMAC, CMAC, GMAC, UMAC, VMAC, Poly1305, SipHash, BLAKE2-MAC, ASCON-MAC |
| AEAD | AES-GCM, AES-CCM, AES-OCB, AES-EAX, ChaCha20-Poly1305, XChaCha20-Poly1305, AEGIS, Deoxys-II, ASCON-AEAD |
| Block Modes | CTR, CFB, OFB, CBC, XTS, CBC-CS |
| DRBG | CTR-DRBG, Hash-DRBG, HMAC-DRBG |
| Encoding | All base encodings, PEM, DER |
| Checksum | All CRCs, Adler32, Fletcher, xxHash |

---

## Security Level Quick Reference

| Level | Classical Equivalent | PQC Equivalent | Algorithms (representative) |
| --- | --- | --- | --- |
| ≤ 64-bit | Broken / Legacy | — | DES, A5/1, MD5, SHA-1 (legacy), RC4 |
| 80-bit | 2DES, SKIPJACK | — | 3DES, SHA-1, DSA-1024, RSA-1024 |
| 112-bit | 3DES, SHA-224 | — | AES-128 (partial), RSA-2048, DH-2048 |
| 128-bit | AES-128, SHA-256 | ML-KEM-512, ML-DSA-44, SLH-DSA-128 | AES-128, ChaCha20, Ed25519, X25519, SHA-256, BLAKE2b |
| 192-bit | AES-192, SHA-384 | ML-KEM-768, ML-DSA-65, SLH-DSA-192 | AES-192, P-384, SHA-384 |
| 256-bit | AES-256, SHA-512 | ML-KEM-1024, ML-DSA-87, SLH-DSA-256 | AES-256, X448, Ed448, SHA-512, SHA3-512, BLAKE3 |

---

*Inventory compiled: 2026-05-09. Status reflects NIST FIPS 203/204/205 final standards (August 2024), SP 800-232 (Ascon, 2024), and OpenSSL 3.5 PQC integration (April 2025).*
