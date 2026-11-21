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

void nextssl__faest_em_256f_r1__rng_set(ns_fill_fn f, void *ctx) { ns_fill = f; ns_ctx = ctx; ns_fail = 0; }
int nextssl__faest_em_256f_r1__rng_failed(void) { return ns_fail; }

/* FAEST's randomness.c declares `extern void randombytes(unsigned char *, unsigned long long)`; the
 * definition must match exactly (wasm traps on a signature mismatch). Failure is reported through
 * ns_fail, which the glue checks after every call. */
void randombytes(unsigned char *output, unsigned long long n) {
    if (n == 0) return;
    if (ns_fill == NULL || ns_fill(ns_ctx, output, n) != 0) {
        memset(output, 0, n);
        ns_fail = 1;
    }
}
