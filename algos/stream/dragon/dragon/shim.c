/* Generated shim (not crypto): one-shot wrapper over the eSTREAM ECRYPT API; it only calls the upstream functions. */
#include <stdlib.h>
#include <string.h>
#include "ecrypt-sync.h"

int shim_apply(const unsigned char *key, int keylen, const unsigned char *iv, int ivlen, unsigned char *data, unsigned int len) {
    unsigned char *raw, *p;
    ECRYPT_ctx *ctx;
    volatile unsigned char *w;
    size_t n = sizeof(ECRYPT_ctx) + 64, i;
    raw = (unsigned char *)calloc(1, n);
    if (raw == NULL) return -1;
    p = raw + ((64 - ((size_t)raw & 63)) & 63);
    ctx = (ECRYPT_ctx *)p;
    ECRYPT_init();
    ECRYPT_keysetup(ctx, key, (u32)keylen * 8, (u32)ivlen * 8);
    ECRYPT_ivsetup(ctx, iv);
    if (len > 0) {
        /* Upstream ECRYPT_process_bytes writes the keystream into `output` before XORing `input`, so input == output
         * (in place) yields all zeros. Feed it a private copy of the input instead. */
        volatile unsigned char *cw;
        unsigned char *copy = (unsigned char *)malloc(len);
        if (copy == NULL) {
            w = raw;
            for (i = 0; i < n; i++) w[i] = 0;
            free(raw);
            return -1;
        }
        memcpy(copy, data, len);
        ECRYPT_process_bytes(0, ctx, copy, data, len);
        cw = copy;
        for (i = 0; i < len; i++) cw[i] = 0;
        free(copy);
    }
    w = raw;
    for (i = 0; i < n; i++) w[i] = 0;
    free(raw);
    return 0;
}
