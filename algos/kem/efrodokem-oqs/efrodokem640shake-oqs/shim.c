/* Shim (not crypto): routes the upstream's random-byte function to the caller's entropy source through a
 * per-thread callback (upstream OS/NIST-DRBG random code is not compiled), and exposes thin one-shot wrappers
 * with fixed names over the upstream kem API. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <oqs/oqs.h>
#include <oqs/kem_frodokem.h>

#if defined(_MSC_VER)
#define NS_TLS __declspec(thread)
#else
#define NS_TLS _Thread_local
#endif

typedef int (*ns_fill_fn)(void *ctx, unsigned char *out, size_t n);
static NS_TLS ns_fill_fn ns_fill;
static NS_TLS void *ns_ctx;
static NS_TLS int ns_fail;

void nextssl__efrodokem640shake_oqs__rng_set(ns_fill_fn f, void *ctx) { ns_fill = f; ns_ctx = ctx; ns_fail = 0; }
int nextssl__efrodokem640shake_oqs__rng_failed(void) { return ns_fail; }

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


int nsw_keypair(uint8_t *pk, uint8_t *sk) { return (int)OQS_KEM_efrodokem_640_shake_keypair(pk, sk) == 0 ? 0 : -1; }
int nsw_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return (int)OQS_KEM_efrodokem_640_shake_encaps(ct, ss, pk) == 0 ? 0 : -1; }
int nsw_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) { return (int)OQS_KEM_efrodokem_640_shake_decaps(ss, ct, sk); }

