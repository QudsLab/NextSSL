/*
 * wasm_selftest.c
 * ───────────────
 * SHA-256 known-answer test used as the WASM module entry point.
 * Returns 0 on success, 1 on failure.
 *
 * KAT: SHA-256("abc") == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 */
#include <stdint.h>
#include <string.h>
#include "primitives/hash/fast/sha256/sha256.h"

static const uint8_t ABC_DIGEST[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

int nextssl_wasm_selftest(void) {
    uint8_t digest[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)"abc", 3);
    sha256_final(&ctx, digest);
    return memcmp(digest, ABC_DIGEST, 32) == 0 ? 0 : 1;
}
