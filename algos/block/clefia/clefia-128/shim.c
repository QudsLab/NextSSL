/* Generated shim (not crypto): owns one upstream CLEFIA key schedule and only calls the upstream functions. */
#include <stdlib.h>
#include <string.h>
#include "clefia_ref.h"

typedef struct {
    unsigned char rk[256];
    int r;
} nsctx;

static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

void *shim_new(const unsigned char *key, int keylen) {
    nsctx *c;
    if (keylen != 16) return NULL;
    c = (nsctx *)calloc(1, sizeof(nsctx));
    if (c == NULL) return NULL;
    c->r = ClefiaKeySet(c->rk, key, keylen * 8);
    if (c->r == 0) {
        wipe(c, sizeof(nsctx));
        free(c);
        return NULL;
    }
    return c;
}

int shim_enc(const void *p, const unsigned char *in, unsigned char *out) {
    const nsctx *c = (const nsctx *)p;
    ClefiaEncrypt(out, in, c->rk, c->r);
    return 0;
}

int shim_dec(const void *p, const unsigned char *in, unsigned char *out) {
    const nsctx *c = (const nsctx *)p;
    ClefiaDecrypt(out, in, c->rk, c->r);
    return 0;
}

void shim_free(void *p) {
    if (p != NULL) {
        wipe(p, sizeof(nsctx));
        free(p);
    }
}
