/* Generated shim (not crypto): routes the upstream's randombytes() to the caller's entropy
 * source through a per-thread callback, so every random byte comes from the nextssl EntropySource. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

void nextssl__kyber1024_90s_r2__rng_set(ns_fill_fn f, void *ctx) { ns_fill = f; ns_ctx = ctx; ns_fail = 0; }
int nextssl__kyber1024_90s_r2__rng_failed(void) { return ns_fail; }

int randombytes(unsigned char *output, unsigned long long n) {
    if (n == 0) return 0;
    if (ns_fill == NULL || ns_fill(ns_ctx, output, n) != 0) {
        ns_spent(output, n);
        ns_fail = 1;
        return -1;
    }
    return 0;
}
