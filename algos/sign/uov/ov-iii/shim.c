/* Shim (not crypto): routes the upstream's random-byte function to the caller's entropy source through a
 * per-thread callback (upstream OS/NIST-DRBG random code is not compiled), and exposes thin one-shot wrappers
 * with fixed names over the upstream sign API. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <oqs/oqs.h>

#if defined(_MSC_VER)
#define NS_TLS __declspec(thread)
#else
#define NS_TLS _Thread_local
#endif

typedef int (*ns_fill_fn)(void *ctx, unsigned char *out, size_t n);
static NS_TLS ns_fill_fn ns_fill;
static NS_TLS void *ns_ctx;
static NS_TLS int ns_fail;

void nextssl__ov_iii__rng_set(ns_fill_fn f, void *ctx) { ns_fill = f; ns_ctx = ctx; ns_fail = 0; }
int nextssl__ov_iii__rng_failed(void) { return ns_fail; }

static int ns_get(unsigned char *output, size_t n) {
    if (n == 0) return 0;
    if (ns_fill == NULL || ns_fill(ns_ctx, output, n) != 0) {
        memset(output, 0, n);
        ns_fail = 1;
        return -1;
    }
    return 0;
}

void OQS_randombytes(uint8_t *out, size_t n) { (void)ns_get(out, n); }


extern int pqov_uov_III_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int pqov_uov_III_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int pqov_uov_III_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
int nsw_keypair(uint8_t *pk, uint8_t *sk) { return (int)pqov_uov_III_ref_keypair(pk, sk) == 0 ? 0 : -1; }
int nsw_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) { return (int)pqov_uov_III_ref_signature(sig, siglen, m, mlen, sk) == 0 ? 0 : -1; }
int nsw_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) { return (int)pqov_uov_III_ref_verify(sig, siglen, m, mlen, pk) == 0 ? 0 : -1; }

