#ifndef NEXTSSL_SEED_KEYGEN_CTX_H
#define NEXTSSL_SEED_KEYGEN_CTX_H

/*
 * keygen_ctx.h — PRIVATE struct definition for keygen_ctx_t.
 *
 * Include ONLY from keygen_fill.c and keygen.c.
 * Never expose this header through public interfaces.
 */

#include <stdint.h>
#include "../drbg/drbg.h"
#include "../udbf/udbf.h"

typedef enum {
    CTX_MODE_RANDOM = 0,  /* Non-deterministic: OS RNG each call          */
    CTX_MODE_UDBF,        /* User Defined Buffer: global udbf module      */
    CTX_MODE_DET          /* Deterministic: DRBG + per-call HKDF-expand   */
} keygen_mode_t;

struct keygen_ctx {
    keygen_mode_t mode;
    DRBG_CTX      drbg;          /* valid only for CTX_MODE_DET            */
    udbf_ctx_t    udbf;          /* valid only for CTX_MODE_UDBF           */
    uint64_t      fill_counter;  /* increments per keygen_fill() call      */
#endif /* NEXTSSL_SEED_KEYGEN_CTX_H */
