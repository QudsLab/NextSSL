/*
 * keygen_fill.c — Internal fill primitive for keygen context.
 *
 * Only keygen.c should call keygen_fill().
 *
 * Three dispatch paths based on ctx->mode:
 *
 *   CTX_MODE_RANDOM:
 *       Calls rng_fill() — OS random, no DRBG involvement.
 *
 *   CTX_MODE_UDBF:
 *       Delegates to udbf_read(label, out, len) which tracks its own
 *       internal state. Returns -3 on exhaustion.
 *
 *   CTX_MODE_DET (DRBG-backed):
 *       1. Pulls 32 fresh DRBG bytes as IKM.
 *       2. Builds info = label || BE64(fill_counter).
 *       3. HKDF-Expand(IKM, info) → len output bytes.
 *       4. Wipes temporaries. fill_counter increments each call so that
 *          repeated calls with the same label still produce distinct output.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "keygen_ctx.h"          /* struct keygen_ctx, keygen_mode_t  */
#include "keygen_fill.h"         /* keygen_fill() declaration          */

#include "../rng/rng.h"
#include "../udbf/udbf.h"
#include "../drbg/drbg.h"
#include "../../PQCrypto/common/hkdf/hkdf.h"

/* Maximum label length accepted (prevents stack overflow in info buffer) */
#define FILL_MAX_LABEL  200u
/* info = label (≤200) + BE64 counter (8) */
#define FILL_INFO_SZ    (FILL_MAX_LABEL + 8u)
/* Maximum output per call — HKDF-SHA256 ceiling: 255 × 32 = 8160 */
#define FILL_MAX_OUT    8160u

int keygen_fill(keygen_ctx_t *ctx, const char *label,
                uint8_t *out, size_t len)
{
    if (!ctx || !out || len == 0 || len > FILL_MAX_OUT)
        return -1;

    switch (ctx->mode) {

    /* ------------------------------------------------------------------ */
    case CTX_MODE_RANDOM:
        return (rng_fill(out, len) == 0) ? 0 : -1;

    /* ------------------------------------------------------------------ */
    case CTX_MODE_UDBF: {
        udbf_result_t r = udbf_read(label, out, len);
        if (r == UDBF_OK)            return  0;
        if (r == UDBF_ERR_EXHAUSTED) return -3;
        return -1;
    }

    /* ------------------------------------------------------------------ */
    case CTX_MODE_DET: {
        /* Step 1: 32 fresh DRBG bytes as IKM */
        uint8_t ikm[32];
        int r = drbg_generate(&ctx->drbg, ikm, sizeof ikm);
        if (r != 0) {
            memset(ikm, 0, sizeof ikm);
            return -2;
        }

        /* Step 2: info = label_bytes || BE64(fill_counter) */
        size_t lab_len = label ? strnlen(label, FILL_MAX_LABEL) : 0;
        uint8_t info[FILL_INFO_SZ];
        if (lab_len) memcpy(info, label, lab_len);

        uint64_t ctr = ctx->fill_counter++;
        for (int i = 7; i >= 0; --i) {
            info[lab_len + (size_t)i] = (uint8_t)(ctr & 0xFF);
            ctr >>= 8;
        }

        /* Step 3: HKDF-Expand → out */
        r = hkdf_expand(ikm, sizeof ikm, info, lab_len + 8, out, len);

        /* Step 4: wipe temporaries */
        memset(ikm,  0, sizeof ikm);
        memset(info, 0, sizeof info);
        return r;
    }

    default:
        return -1;
    }
}
