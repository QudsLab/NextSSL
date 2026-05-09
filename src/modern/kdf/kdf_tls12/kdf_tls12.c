/* kdf_tls12.c — TLS 1.2 PRF (RFC 5246 §5) using HMAC-SHA256 */
#include "kdf_tls12.h"
#include "../../mac/hmac/hmac.h"
#include <string.h>

/* P_hash expansion (RFC 5246 §5) */
static int p_hash(const uint8_t *secret,  size_t secret_len,
                  const uint8_t *seed_full, size_t seed_full_len,
                  uint8_t *out, size_t out_len,
                  int use_sha384)
{
    /* A(0) = seed */
    uint8_t A[64]; /* max(SHA256=32, SHA384=48) */
    size_t hlen = use_sha384 ? 48 : 32;

    /* A(1) = HMAC(secret, A(0)) */
    if (hmac_compute(use_sha384 ? HMAC_SHA384 : HMAC_SHA256,
                      secret, secret_len,
                      seed_full, seed_full_len,
                      A, NULL) != 0) return -1;

    size_t done = 0;
    while (done < out_len) {
        /* HMAC(secret, A(i) || seed) */
        uint8_t hmac_in[64 + 512];
        if (seed_full_len + hlen > sizeof(hmac_in)) return -1;
        memcpy(hmac_in, A, hlen);
        memcpy(hmac_in + hlen, seed_full, seed_full_len);

        uint8_t tmp[64];
        if (hmac_compute(use_sha384 ? HMAC_SHA384 : HMAC_SHA256,
                          secret, secret_len,
                          hmac_in, hlen + seed_full_len,
                          tmp, NULL) != 0) return -1;

        size_t take = (out_len - done < hlen) ? (out_len - done) : hlen;
        memcpy(out + done, tmp, take);
        done += take;

        /* A(i+1) = HMAC(secret, A(i)) */
        if (done < out_len) {
            if (hmac_compute(use_sha384 ? HMAC_SHA384 : HMAC_SHA256,
                              secret, secret_len,
                              A, hlen,
                              A, NULL) != 0) return -1;
        }
    }
    return 0;
}

static int tls12_prf_inner(const uint8_t *secret, size_t secret_len,
                            const char *label, size_t label_len,
                            const uint8_t *seed, size_t seed_len,
                            uint8_t *out, size_t out_len, int use_sha384)
{
    if (!secret || !label || !out) return -1;
    /* Concatenate label || seed */
    uint8_t full_seed[256 + 64];
    if (label_len + seed_len > sizeof(full_seed)) return -1;
    memcpy(full_seed, label, label_len);
    if (seed && seed_len) memcpy(full_seed + label_len, seed, seed_len);

    return p_hash(secret, secret_len,
                  full_seed, label_len + seed_len,
                  out, out_len, use_sha384);
}

int tls12_prf(const uint8_t *secret,  size_t secret_len,
              const char    *label,   size_t label_len,
              const uint8_t *seed,    size_t seed_len,
              uint8_t       *out,     size_t out_len)
{
    return tls12_prf_inner(secret, secret_len, label, label_len,
                            seed, seed_len, out, out_len, 0);
}

int tls12_prf_sha384(const uint8_t *secret,  size_t secret_len,
                      const char    *label,   size_t label_len,
                      const uint8_t *seed,    size_t seed_len,
                      uint8_t       *out,     size_t out_len)
{
    return tls12_prf_inner(secret, secret_len, label, label_len,
                            seed, seed_len, out, out_len, 1);
}

int tls12_master_secret(const uint8_t pre_master[48],
                         const uint8_t client_random[32],
                         const uint8_t server_random[32],
                         uint8_t       master[48])
{
    uint8_t seed[64];
    memcpy(seed,      client_random, 32);
    memcpy(seed + 32, server_random, 32);
    return tls12_prf(pre_master, 48, "master secret", 13, seed, 64, master, 48);
}

int tls12_key_expansion(const uint8_t master[48],
                         const uint8_t server_random[32],
                         const uint8_t client_random[32],
                         uint8_t *key_block, size_t key_block_len)
{
    uint8_t seed[64];
    memcpy(seed,      server_random, 32);
    memcpy(seed + 32, client_random, 32);
    return tls12_prf(master, 48, "key expansion", 13, seed, 64,
                     key_block, key_block_len);
}
