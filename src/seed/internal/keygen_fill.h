#ifndef NEXTSSL_SEED_KEYGEN_FILL_H
#define NEXTSSL_SEED_KEYGEN_FILL_H

/*
 * keygen_fill.h — PRIVATE internal primitive.
 *
 * NEVER include this header from outside src/seed/.
 * Called exclusively by the keygen_<algo>() wrappers in keygen.c.
 *
 * Fills `len` bytes into `out` from the context's internal engine, using
 * `label` for domain separation. Two calls with different labels produce
 * independent outputs even from the same context.
 *
 * @return  0 on success
 *         -1 on invalid arguments
 *         -2 if DRBG reseed limit exceeded
 *         -3 if UDBF is exhausted
 */

/* Forward declaration — full struct is in keygen.c (opaque to callers) */
typedef struct keygen_ctx keygen_ctx_t;

int keygen_fill(keygen_ctx_t *ctx, const char *label,
                uint8_t *out, size_t len);

#endif /* NEXTSSL_SEED_KEYGEN_FILL_H */
