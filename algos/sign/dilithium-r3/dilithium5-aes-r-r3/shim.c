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

void nextssl__dilithium5_aes_r_r3__rng_set(ns_fill_fn f, void *ctx) { ns_fill = f; ns_ctx = ctx; ns_fail = 0; }
int nextssl__dilithium5_aes_r_r3__rng_failed(void) { return ns_fail; }

int randombytes(unsigned char *output, unsigned long long n) {
    if (n == 0) return 0;
    if (ns_fill == NULL || ns_fill(ns_ctx, output, n) != 0) {
        memset(output, 0, n);
        ns_fail = 1;
        return -1;
    }
    return 0;
}
