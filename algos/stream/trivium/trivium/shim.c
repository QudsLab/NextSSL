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
    if (len > 0) ECRYPT_process_bytes(0, ctx, data, data, len);
    w = raw;
    for (i = 0; i < n; i++) w[i] = 0;
    free(raw);
    return 0;
}
