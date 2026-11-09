#include <stdlib.h>
#include <string.h>
#include "kalyna.h"

/* NextSSL adapter (not upstream code): opaque context, byte <-> 64-bit little-endian word conversion. */
static const int BITS_BLOCK[] = {128, 128, 256, 256, 512};
static const int BITS_KEY[] = {128, 256, 256, 512, 512};

typedef struct {
    kalyna_t *k;
    int nb;
} kctx;

static void to_words(uint64_t *w, const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) {
        uint64_t x = 0;
        for (int j = 7; j >= 0; j--) x = (x << 8) | b[8 * i + j];
        w[i] = x;
    }
}
static void to_bytes(unsigned char *b, const uint64_t *w, int n) {
    for (int i = 0; i < n; i++)
        for (int j = 0; j < 8; j++) b[8 * i + j] = (unsigned char)(w[i] >> (8 * j));
}

void *nextssl__kalyna_256_512__new(int v, const unsigned char *key) {
    if (v < 0 || v > 4) return NULL;
    kctx *c = (kctx *)calloc(1, sizeof *c);
    if (!c) return NULL;
    c->k = KalynaInit((size_t)BITS_BLOCK[v], (size_t)BITS_KEY[v]);
    if (!c->k) { free(c); return NULL; }
    c->nb = BITS_BLOCK[v] / 64;
    uint64_t kw[8];
    to_words(kw, key, BITS_KEY[v] / 64);
    KalynaKeyExpand(kw, c->k);
    memset(kw, 0, sizeof kw);
    return c;
}

int nextssl__kalyna_256_512__enc(void *p, const unsigned char *in, unsigned char *out) {
    kctx *c = (kctx *)p;
    uint64_t a[8], b[8];
    to_words(a, in, c->nb);
    KalynaEncipher(a, c->k, b);
    to_bytes(out, b, c->nb);
    return 0;
}

int nextssl__kalyna_256_512__dec(void *p, const unsigned char *in, unsigned char *out) {
    kctx *c = (kctx *)p;
    uint64_t a[8], b[8];
    to_words(a, in, c->nb);
    KalynaDecipher(a, c->k, b);
    to_bytes(out, b, c->nb);
    return 0;
}

void nextssl__kalyna_256_512__free(void *p) {
    kctx *c = (kctx *)p;
    if (!c) return;
    KalynaDelete(c->k);
    free(c);
}
