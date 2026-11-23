/* Shim (not crypto): (1) routes libecc's get_random()/get_unsafe_random() to the caller's entropy source
 * through a per-thread callback, so no random byte ever comes from the OS (libecc's own rand.c is not
 * compiled); (2) thin one-shot wrappers over the libecc key and signature API for one fixed
 * scheme x curve x hash combination (NS_SIG, NS_CURVE, NS_HASH). */
#include <stddef.h>
#include <string.h>
#include "libsig.h"
#include "external_deps/rand.h"

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

void shim_rng_set(ns_fill_fn f, void *ctx) { ns_fill = f; ns_ctx = ctx; ns_fail = 0; }
int shim_rng_failed(void) { return ns_fail; }

/* Public-input mode. libecc asks get_random() even for operations that take no randomness argument
 * (verification, public key derivation from a given scalar), where it only randomizes projective
 * coordinates against side channels; the result does not depend on those bytes. Without an installed
 * entropy callback these calls get a fixed non-cryptographic xorshift64* stream instead of the OS RNG.
 * Signing nonces and key generation never take this path: they run with the caller's callback installed
 * and fail (ns_fail) if it does. */
static NS_TLS int ns_public_mode;
static NS_TLS unsigned long long ns_xs;

static void public_fill(unsigned char *buf, size_t n)
{
    size_t i;
    if (ns_xs == 0) ns_xs = 0x9E3779B97F4A7C15ull;
    for (i = 0; i < n; i++) {
        ns_xs ^= ns_xs >> 12; ns_xs ^= ns_xs << 25; ns_xs ^= ns_xs >> 27;
        buf[i] = (unsigned char)((ns_xs * 0x2545F4914F6CDD1Dull) >> 56);
    }
}

int get_random(unsigned char *buf, u16 len)
{
    if (len == 0) return 0;
    if (ns_fill == NULL && ns_public_mode) { public_fill(buf, (size_t)len); return 0; }
    if (ns_fill == NULL || ns_fill(ns_ctx, buf, (size_t)len) != 0) {
        ns_spent(buf, len);
        ns_fail = 1;
        return -1;
    }
    return 0;
}

int get_unsafe_random(unsigned char *buf, u16 len) { return get_random(buf, len); }

static int load_params(ec_params *p)
{
    const ec_str_params *sp;
    if (ec_get_curve_params_by_type(NS_CURVE, &sp)) return -1;
    if (import_params(p, sp)) return -1;
    return 0;
}

int shim_sizes(unsigned *sk, unsigned *pk, unsigned *sig)
{
    ec_params p;
    u8 sl = 0;
    if (load_params(&p)) return -1;
    if (ec_get_sig_len(&p, NS_SIG, NS_HASH, &sl)) return -1;
    *sk = BYTECEIL(p.ec_gen_order_bitlen);
    *pk = 2u * BYTECEIL(p.ec_fp.p_bitlen);
    *sig = sl;
    return 0;
}

static int export_pair(const ec_key_pair *kp, unsigned sklen, unsigned pklen, unsigned char *sk, unsigned char *pk)
{
    if (sk != NULL && ec_priv_key_export_to_buf(&kp->priv_key, sk, (u8)sklen)) return -1;
    if (pk != NULL && ec_pub_key_export_to_aff_buf(&kp->pub_key, pk, (u8)pklen)) return -1;
    return 0;
}

/* Some schemes (EC-SDSA, EC-OSDSA) do not range-check the private scalar themselves: refuse 0 and anything >= q here
 * (the Sign contract rejects invalid keys, never reduces them silently). Returns 0 when 0 < x < q. */
static int priv_in_range(const ec_key_pair *kp, const ec_params *p)
{
    int z = 1, c = 0;
    if (nn_iszero(&kp->priv_key.x, &z) || z) return -1;
    if (nn_cmp(&kp->priv_key.x, &p->ec_gen_order, &c) || c >= 0) return -1;
    return 0;
}

int shim_keygen(unsigned char *sk, unsigned char *pk)
{
    ec_params p;
    ec_key_pair kp;
    unsigned a, b, c;
    int rc = -1;
    if (shim_sizes(&a, &b, &c)) return -1;
    if (load_params(&p)) return -1;
    if (ec_key_pair_gen(&kp, &p, NS_SIG)) goto done;
    if (export_pair(&kp, a, b, sk, pk)) goto done;
    rc = 0;
done:
    memset(&kp, 0, sizeof(kp));
    return rc;
}

/* sk is the private scalar, big-endian, exactly the order length in bytes; rejected unless 0 < sk < q. */
int shim_pk_from_sk(const unsigned char *sk, unsigned char *pk)
{
    ec_params p;
    ec_key_pair kp;
    unsigned a, b, c;
    int rc = -1;
    if (shim_sizes(&a, &b, &c)) return -1;
    if (load_params(&p)) return -1;
    ns_public_mode = 1;
    if (ec_key_pair_import_from_priv_key_buf(&kp, &p, sk, (u8)a, NS_SIG)) goto done;
    if (priv_in_range(&kp, &p)) goto done;
    if (export_pair(&kp, a, b, NULL, pk)) goto done;
    rc = 0;
done:
    ns_public_mode = 0;
    memset(&kp, 0, sizeof(kp));
    return rc;
}

int shim_sign(const unsigned char *sk, const unsigned char *msg, unsigned long mlen, unsigned char *sig)
{
    ec_params p;
    ec_key_pair kp;
    unsigned a, b, c;
    int rc = -1;
    if (mlen > 0xFFFFFFFFul) return -1;
    if (shim_sizes(&a, &b, &c)) return -1;
    if (load_params(&p)) return -1;
    if (ec_key_pair_import_from_priv_key_buf(&kp, &p, sk, (u8)a, NS_SIG)) goto done;
    if (priv_in_range(&kp, &p)) goto done;
    if (ec_sign(sig, (u8)c, &kp, msg, (u32)mlen, NS_SIG, NS_HASH, NULL, 0)) goto done;
    rc = 0;
done:
    memset(&kp, 0, sizeof(kp));
    return rc;
}

/* 1 = valid, 0 = well-formed but invalid, -1 = malformed key or signature or internal error. */
int shim_verify(const unsigned char *pk, const unsigned char *msg, unsigned long mlen, const unsigned char *sig)
{
    ec_params p;
    ec_pub_key pub;
    unsigned a, b, c;
    int rc;
    if (mlen > 0xFFFFFFFFul) return -1;
    if (shim_sizes(&a, &b, &c)) return -1;
    if (load_params(&p)) return -1;
    ns_public_mode = 1;
    if (ec_pub_key_import_from_aff_buf(&pub, &p, pk, (u8)b, NS_SIG)) { ns_public_mode = 0; return -1; }
    rc = ec_verify(sig, (u8)c, &pub, msg, (u32)mlen, NS_SIG, NS_HASH, NULL, 0) == 0 ? 1 : 0;
    ns_public_mode = 0;
    return rc;
}
