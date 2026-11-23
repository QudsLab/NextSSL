/* Shim (not crypto): routes the upstream's randombytes() to the caller's entropy source through a per-thread callback
 * (upstream randombytes.c, which reads /dev/urandom, is not compiled) and exposes one-shot wrappers with fixed names that
 * select the XMSS or XMSS^MT entry point. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "xmss.h"
#include "xmss_core.h"
#include "randombytes.h"
#include <openssl/sha.h>
#include <oqs/sha2.h>

#if defined(_MSC_VER)
#define NS_TLS __declspec(thread)
#else
#define NS_TLS _Thread_local
#endif

typedef int (*ns_fill_fn)(void *ctx, unsigned char *out, size_t n);
static NS_TLS ns_fill_fn ns_fill;
static NS_TLS void *ns_ctx;
static NS_TLS int ns_fail;
/* Entropy source failed: the call returns an error and its output is discarded, but the upstream
 * may retry (rejection sampling, invertibility loops) until it gets usable bytes. Zeros would make
 * such a loop endless, so fill with a non-repeating, non-secret counter stream (splitmix64). */
static NS_TLS unsigned long long ns_spent_ctr;
static void ns_spent(void *out, size_t n) {
    unsigned char *p = (unsigned char *)out;
    for (size_t i = 0; i < n; i++) {
        unsigned long long x = (++ns_spent_ctr) * 0x9E3779B97F4A7C15ULL;
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
        p[i] = (unsigned char)(x ^ (x >> 31));
    }
}

void nextssl__xmssmt_sha2_20_4_192__rng_set(ns_fill_fn f, void *ctx) { ns_fill = f; ns_ctx = ctx; ns_fail = 0; }
int nextssl__xmssmt_sha2_20_4_192__rng_failed(void) { return ns_fail; }

void randombytes(unsigned char *x, unsigned long long xlen) {
    if (xlen == 0) return;
    if (ns_fill == NULL || ns_fill(ns_ctx, x, (size_t)xlen) != 0) {
        ns_spent(x, (size_t)xlen);
        ns_fail = 1;
    }
}

int nsw_keypair(unsigned char *pk, unsigned char *sk, uint32_t oid, int mt) {
    return mt ? xmssmt_keypair(pk, sk, oid) : xmss_keypair(pk, sk, oid);
}

/* seed is 3*n bytes: SK_SEED || SK_PRF || PUB_SEED. Writes the same [OID || ...] formats as xmss[mt]_keypair. */
int nsw_keypair_seed(unsigned char *pk, unsigned char *sk, uint32_t oid, int mt, unsigned char *seed) {
    xmss_params params;
    int i;
    if (mt ? xmssmt_parse_oid(&params, oid) : xmss_parse_oid(&params, oid)) return -1;
    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (unsigned char)((oid >> (8 * i)) & 0xFF);
        sk[XMSS_OID_LEN - i - 1] = (unsigned char)((oid >> (8 * i)) & 0xFF);
    }
    return xmssmt_core_seed_keypair(&params, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN, seed);
}

int nsw_sign(unsigned char *sk, unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, int mt) {
    return mt ? xmssmt_sign(sk, sm, smlen, m, mlen) : xmss_sign(sk, sm, smlen, m, mlen);
}

int nsw_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk, int mt) {
    return mt ? xmssmt_sign_open(m, mlen, sm, smlen, pk) : xmss_sign_open(m, mlen, sm, smlen, pk);
}

/* OpenSSL-compatible one-shot SHA-2 over liboqs plain C implementation (hash.c calls these). */
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md) { OQS_SHA2_sha256(md, d, n); return md; }
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md) { OQS_SHA2_sha512(md, d, n); return md; }
