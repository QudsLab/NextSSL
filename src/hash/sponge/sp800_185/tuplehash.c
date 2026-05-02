/* tuplehash.c — TupleHash-128 and TupleHash-256 (NIST SP 800-185 §5) */
#include "tuplehash.h"
#include "cshake.h"
#include <string.h>

/* SP 800-185 encoding primitives (local) */
static size_t th_left_encode(uint64_t x, uint8_t *buf)
{
    uint8_t tmp[8];
    size_t n = 0;
    if (x == 0) { buf[0] = 1; buf[1] = 0; return 2; }
    uint64_t v = x;
    while (v) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    buf[0] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) buf[1 + i] = tmp[n - 1 - i];
    return 1 + n;
}

static size_t th_right_encode(uint64_t x, uint8_t *buf)
{
    uint8_t tmp[8];
    size_t n = 0;
    if (x == 0) { buf[0] = 0; buf[1] = 1; return 2; }
    uint64_t v = x;
    while (v) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    for (size_t i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    buf[n] = (uint8_t)n;
    return n + 1;
}

static const uint8_t N_tuplehash[] = {
    'T','u','p','l','e','H','a','s','h'
};

static int tuplehash_impl(int bits128,
                           const tuplehash_entry_t *entries, size_t n_entries,
                           const uint8_t *S, size_t Slen,
                           uint8_t *out, size_t outlen)
{
    if (!out || outlen == 0) return -1;

    CSHAKE_CTX ctx;
    if (bits128)
        cshake128_init(&ctx, N_tuplehash, sizeof(N_tuplehash), S, Slen);
    else
        cshake256_init(&ctx, N_tuplehash, sizeof(N_tuplehash), S, Slen);

    /* Absorb encode_string(X[i]) for each tuple entry */
    for (size_t i = 0; i < n_entries; i++) {
        uint8_t enc[9];
        size_t enc_len = th_left_encode(
            (entries[i].data && entries[i].len) ? (uint64_t)entries[i].len * 8 : 0,
            enc);
        cshake_update(&ctx, enc, enc_len);
        if (entries[i].data && entries[i].len)
            cshake_update(&ctx, entries[i].data, entries[i].len);
    }

    /* Absorb right_encode(L) where L = outlen * 8 */
    uint8_t r_enc[9];
    size_t r_len = th_right_encode((uint64_t)outlen * 8, r_enc);
    cshake_update(&ctx, r_enc, r_len);

    cshake_squeeze(&ctx, out, outlen);
    return 0;
}

int tuplehash128(const tuplehash_entry_t *entries, size_t n_entries,
                 const uint8_t *S, size_t Slen,
                 uint8_t *out, size_t outlen)
{
    return tuplehash_impl(1, entries, n_entries, S, Slen, out, outlen);
}

int tuplehash256(const tuplehash_entry_t *entries, size_t n_entries,
                 const uint8_t *S, size_t Slen,
                 uint8_t *out, size_t outlen)
{
    return tuplehash_impl(0, entries, n_entries, S, Slen, out, outlen);
}
