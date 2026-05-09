/* sosemanuk.h — SOSEMANUK stream cipher (eSTREAM portfolio winner)
 *
 * SOSEMANUK combines a 10-stage LFSR with a finite automaton (Serpent S-boxes)
 * producing 80 bytes per step.  Key: 128..256 bits. IV: 128 bits.
 *
 * Reference: https://www.ecrypt.eu.org/stream/sosemanukpf.html
 *            Berbain et al., "SOSEMANUK, a Fast Software-Oriented Stream Cipher"
 *
 * TODO: Full SOSEMANUK requires the Serpent S-box lookup tables (~4KB).
 *       This header provides the API surface; the implementation is a
 *       structural stub pending a Serpent S-box integration.
 */
#ifndef NEXTSSL_SOSEMANUK_H
#define NEXTSSL_SOSEMANUK_H

#include <stdint.h>
#include <stddef.h>

#define SOSEMANUK_KEY_MIN_SIZE  16u  /* 128-bit minimum */
#define SOSEMANUK_KEY_MAX_SIZE  32u  /* 256-bit maximum */
#define SOSEMANUK_IV_SIZE       16u  /* 128-bit IV */

typedef struct {
    uint32_t s[10];    /* LFSR state */
    uint32_t r1, r2;  /* FSM registers */
    uint32_t subkeys[100]; /* Serpent round keys */
} sosemanuk_ctx;

/* sosemanuk_init — Initialize SOSEMANUK.
 * key_len must be 16..32 bytes.
 * Returns 0 on success. */
int sosemanuk_init(sosemanuk_ctx *ctx,
                    const uint8_t *key, size_t key_len,
                    const uint8_t  iv[SOSEMANUK_IV_SIZE]);

void sosemanuk_keystream(sosemanuk_ctx *ctx, uint8_t *buf, size_t len);
void sosemanuk_xor(sosemanuk_ctx *ctx,
                    const uint8_t *in, uint8_t *out, size_t len);

#endif /* NEXTSSL_SOSEMANUK_H */
