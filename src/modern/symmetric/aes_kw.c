#include "aes_kw.h"
#include "aes_internal.h"

char AES_KEY_wrap( const uint8_t* kek,
                   const void* secret, const size_t secretLen, void* wrapped )
{
    uint8_t *w = wrapped;
    uint8_t *r = w + HB, *endpoint = w + secretLen;
    block_t A;
    count_t i, n = secretLen / HB;

    if (n < 2 || secretLen % HB)  return M_DATALENGTH_ERROR;

    memset( A, 0xA6, HB );
    memcpy( r, secret, secretLen );
    AES_setkey( kek );

    for (i = 0, n *= 6; i++ < n; )
    {
        memcpy( A + HB, r, HB );
        rijndaelEncrypt( A, A );
        memcpy( r, A + HB, HB );
        xorBEint( A, i, MIDST );
        r = (r == endpoint ? w : r) + HB;
    }
    AES_burn();

    memcpy( w, A, HB );
    return M_RESULT_SUCCESS;
}

char AES_KEY_unwrap( const uint8_t* kek,
                     const void* wrapped, const size_t wrapLen, void* secret )
{
    uint8_t const* w = wrapped;
    uint8_t *r = secret, *end = (uint8_t*) secret + wrapLen - HB;
    block_t A;
    count_t i, n = wrapLen / HB;

    if (n < 0x3 || wrapLen % HB)  return M_DATALENGTH_ERROR;

    memcpy( A, w, HB );
    memcpy( r, w + HB, wrapLen - HB );
    AES_setkey( kek );

    for (--n, i = n * 6; i; --i)
    {
        r = (r == secret ? end : r) - HB;
        xorBEint( A, i, MIDST );
        memcpy( A + HB, r, HB );
        rijndaelDecrypt( A, A );
        memcpy( r, A + HB, HB );
    }
    AES_burn();

    for (n = 0, i = HB; i--; )
    {
        n |= A[i] - 0xA6;
    }
    return n ? M_AUTHENTICATION_ERROR : M_RESULT_SUCCESS;
}

/* =========================================================================
 * AES Key Wrap with Padding (SP 800-38F §6.3)
 *
 * KWP differs from KW in its ICV: instead of 0xA6A6A6A6A6A6A6A6 (8 bytes),
 * KWP uses the 4-byte constant 0xA65959A6 followed by the 4-byte big-endian
 * plaintext length, followed by zero-padding to the next 8-byte boundary.
 *
 * Wrapped output = KW(padded_input)  where padded_input = ICV_8 || plaintext_padded
 *                                    and ICV_8 = 0xA65959A6 || BE32(secretLen)
 * ========================================================================= */

#include <stdlib.h>

/* Write 32-bit big-endian value into buf[0..3] */
static void kwp_write_be32(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)(v >> 24);
    buf[1] = (uint8_t)(v >> 16);
    buf[2] = (uint8_t)(v >>  8);
    buf[3] = (uint8_t)(v      );
}

static uint32_t kwp_read_be32(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
         | ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
}

char AES_KWP_wrap(const uint8_t *kek,
                  const void    *secret,  size_t  secretLen,
                  void          *wrapped, size_t *wrappedLen)
{
    if (!kek || !secret || secretLen == 0 || !wrapped || !wrappedLen)
        return (char)M_DATALENGTH_ERROR;

    /* Padded plaintext length (round up to 8-byte boundary) */
    size_t padded = ((secretLen + 7) / 8) * 8;

    /* Build the KWP plaintext: padded_secret (zero-padded) */
    uint8_t *plain = (uint8_t *)malloc(padded);
    if (!plain) return (char)M_ENCRYPTION_ERROR;
    memcpy(plain, secret, secretLen);
    if (padded > secretLen)
        memset(plain + secretLen, 0, padded - secretLen);

    /* Build the AIV (Alternative Initial Value): 0xA65959A6 || BE32(secretLen) */
    uint8_t aiv[HB];  /* HB = 8 */
    aiv[0] = 0xA6; aiv[1] = 0x59; aiv[2] = 0x59; aiv[3] = 0xA6;
    kwp_write_be32(aiv + 4, (uint32_t)secretLen);

    /* Build full wrap input: AIV || padded_plain (as if aiv is the first semiblock) */
    size_t wrap_in_len = HB + padded;
    uint8_t *wrap_in = (uint8_t *)malloc(wrap_in_len);
    if (!wrap_in) { free(plain); return (char)M_ENCRYPTION_ERROR; }
    memcpy(wrap_in, aiv, HB);
    memcpy(wrap_in + HB, plain, padded);
    free(plain);

    /* Special case: secretLen <= 8 — use a single AES block encrypt (no W-cycle) */
    if (padded == HB) {
        AES_setkey(kek);
        rijndaelEncrypt(wrap_in, (uint8_t *)wrapped);
        AES_burn();
        *wrappedLen = 16;
        free(wrap_in);
        return (char)M_RESULT_SUCCESS;
    }

    /* General case: same W-cycle as KW but over wrap_in */
    char rc = AES_KEY_wrap(kek, wrap_in + HB, padded, wrapped);
    /* AES_KEY_wrap prepends its own A[0..7] — but for KWP we supply our own AIV.
     * We must run the W-cycle ourselves with the KWP AIV. */
    /* Redo manually with the KWP AIV */
    uint8_t *w = (uint8_t *)wrapped;
    uint8_t *r = w + HB;
    uint8_t *endpoint = w + padded;
    block_t A;
    count_t i, rounds = (padded / HB) * 6;

    memcpy(A, aiv, HB);
    memcpy(r, wrap_in + HB, padded);
    free(wrap_in);

    AES_setkey(kek);
    for (i = 0; i++ < rounds; ) {
        memcpy(A + HB, r, HB);
        rijndaelEncrypt(A, A);
        memcpy(r, A + HB, HB);
        xorBEint(A, i, MIDST);
        r = (r == endpoint ? w : r) + HB;
    }
    AES_burn();
    memcpy(w, A, HB);
    *wrappedLen = padded + HB;
    return (char)M_RESULT_SUCCESS;
}

char AES_KWP_unwrap(const uint8_t *kek,
                    const void    *wrapped, size_t  wrapLen,
                    void          *secret,  size_t *secretLen)
{
    if (!kek || !wrapped || wrapLen < 16 || !secret || !secretLen)
        return (char)M_DATALENGTH_ERROR;
    if (wrapLen % HB != 0) return (char)M_DATALENGTH_ERROR;

    size_t padded = wrapLen - HB;

    /* Special case: 16-byte wrapped data = single AES block decrypt */
    if (wrapLen == 16) {
        block_t plain;
        AES_setkey(kek);
        rijndaelDecrypt((const uint8_t *)wrapped, plain);
        AES_burn();
        if (plain[0]!=0xA6||plain[1]!=0x59||plain[2]!=0x59||plain[3]!=0xA6)
            return (char)M_AUTHENTICATION_ERROR;
        uint32_t plen = kwp_read_be32(plain + 4);
        if (plen > 8) return (char)M_AUTHENTICATION_ERROR;
        memcpy(secret, plain + HB, plen);
        *secretLen = plen;
        return (char)M_RESULT_SUCCESS;
    }

    /* General unwrap: run reverse W-cycle */
    uint8_t *w   = (uint8_t *)malloc(wrapLen);
    if (!w) return (char)M_DECRYPTION_ERROR;
    memcpy(w, wrapped, wrapLen);

    uint8_t *r   = (uint8_t *)malloc(padded);
    if (!r) { free(w); return (char)M_DECRYPTION_ERROR; }

    block_t A;
    count_t i, rounds = (padded / HB) * 6;
    uint8_t *end = r + padded - HB;

    memcpy(A, w, HB);
    memcpy(r, w + HB, padded);
    free(w);

    AES_setkey(kek);
    for (i = rounds; i; --i) {
        uint8_t *rp = (r == r ? end : r); /* placeholder — compute pointer correctly */
        /* Pointer arithmetic mirrors KW unwrap */
        size_t blk_idx = ((i - 1) % (padded / HB));
        uint8_t *block = r + blk_idx * HB;
        xorBEint(A, i, MIDST);
        memcpy(A + HB, block, HB);
        rijndaelDecrypt(A, A);
        memcpy(block, A + HB, HB);
        (void)rp;
    }
    AES_burn();

    /* Verify KWP AIV */
    if (A[0]!=0xA6||A[1]!=0x59||A[2]!=0x59||A[3]!=0xA6) {
        free(r); return (char)M_AUTHENTICATION_ERROR;
    }
    uint32_t plen = kwp_read_be32(A + 4);
    if (plen > padded || plen + (8 - plen % 8) % 8 != padded) {
        free(r); return (char)M_AUTHENTICATION_ERROR;
    }
    /* Verify zero padding */
    for (size_t j = plen; j < padded; j++) {
        if (r[j] != 0) { free(r); return (char)M_AUTHENTICATION_ERROR; }
    }
    memcpy(secret, r, plen);
    *secretLen = plen;
    free(r);
    return (char)M_RESULT_SUCCESS;
}
