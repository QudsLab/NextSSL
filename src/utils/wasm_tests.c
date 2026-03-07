/*
 * wasm_tests.c
 * ────────────
 * Per-module functional KAT entry points for WASM CI testing.
 * Each function returns 0 on PASS, non-zero on FAIL (error code).
 * Called via: wasmtime --invoke nextssl_wasm_test_<name> <module>.wasm
 * The runner checks that stdout prints "0".
 *
 * Compile-time guards select which tests are included per module:
 *   WASM_TEST_HASH  → nextssl_wasm_test_sha256
 *   WASM_TEST_CORE  → nextssl_wasm_test_aes_cbc
 *   WASM_TEST_PQC   → nextssl_wasm_test_mlkem512
 *   WASM_TEST_POW   → nextssl_wasm_test_dhcm
 */

#include <stdint.h>
#include <string.h>

/* ══════════════════════════════════════════════════════════════════
 * HASH — SHA-256("abc") KAT
 * ══════════════════════════════════════════════════════════════════ */
#ifdef WASM_TEST_HASH

#include "utils/hash/primitive_fast.h"

int nextssl_wasm_test_sha256(void) {
    static const uint8_t input[3] = {'a', 'b', 'c'};
    static const uint8_t expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad,
    };
    uint8_t digest[32];
    nextssl_sha256(input, 3, digest);
    return memcmp(digest, expected, 32) == 0 ? 0 : 1;
}

#endif /* WASM_TEST_HASH */


/* ══════════════════════════════════════════════════════════════════
 * CORE — AES-128-CBC NIST KAT (FIPS 197, first test vector)
 *   Key : 2b7e151628aed2a6abf7158809cf4f3c
 *   IV  : 000102030405060708090a0b0c0d0e0f
 *   PT  : 6bc1bee22e409f96e93d7e117393172a
 *   CT  : 7649abac8119b246cee98e9b12e9197d
 * ══════════════════════════════════════════════════════════════════ */
#ifdef WASM_TEST_CORE

#include "primitives/cipher/aes_cbc/aes_cbc.h"

int nextssl_wasm_test_aes_cbc(void) {
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    };
    static const uint8_t pt[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    };
    static const uint8_t expected[16] = {
        0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
        0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
    };
    uint8_t ct[16];
    AES_CBC_encrypt(key, iv, pt, 16, ct);
    return memcmp(ct, expected, 16) == 0 ? 0 : 1;
}

#endif /* WASM_TEST_CORE */


/* ══════════════════════════════════════════════════════════════════
 * PQC — ML-KEM-512 keygen → encaps → decaps round-trip
 *   No fixed KAT needed: just verify ss_enc == ss_dec after decaps.
 * ══════════════════════════════════════════════════════════════════ */
#ifdef WASM_TEST_PQC

/* Forward declarations — defined in pqc_main.c, exported symbols */
extern int pqc_mlkem512_keypair(uint8_t *pk, uint8_t *sk);
extern int pqc_mlkem512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mlkem512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int nextssl_wasm_test_mlkem512(void) {
    /* ML-KEM-512 sizes per FIPS 203 */
    uint8_t pk[800], sk[1632], ct[768], ss_enc[32], ss_dec[32];

    if (pqc_mlkem512_keypair(pk, sk)        != 0) return 1;
    if (pqc_mlkem512_encaps(ct, ss_enc, pk) != 0) return 2;
    if (pqc_mlkem512_decaps(ss_dec, ct, sk) != 0) return 3;
    /* Shared secrets must match */
    return memcmp(ss_enc, ss_dec, 32) == 0 ? 0 : 4;
}

#endif /* WASM_TEST_PQC */


/* ══════════════════════════════════════════════════════════════════
 * POW — DHCM expected-trials calculation (no struct construction needed)
 *   SHA-256 target-based with 8 leading zero bits → E[trials] = 256.
 * ══════════════════════════════════════════════════════════════════ */
#ifdef WASM_TEST_POW

#include "DHCM/core/dhcm_types.h"
#include "DHCM/utils/dhcm_api.h"

int nextssl_wasm_test_dhcm(void) {
    /*
     * nextssl_dhcm_expected_trials(DHCM_DIFFICULTY_TARGET_BASED, 8)
     * For SHA-256 with 8 leading-zero bits: E[N] = 2^8 = 256.0
     */
    double trials = nextssl_dhcm_expected_trials(DHCM_DIFFICULTY_TARGET_BASED, 8);
    /* Must be positive; exact value is 256.0 */
    if (trials <= 0.0) return 1;
    /* Cast to int for exact check: 256 */
    return ((int)trials == 256) ? 0 : 2;
}

#endif /* WASM_TEST_POW */
