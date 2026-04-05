/* sm2.c — SM2 signature and encryption wrappers (GmSSL backend)
 *
 * Links against libgmssl.  All heavy lifting is in GmSSL's sm2_sign.c
 * and sm2_enc.c; this file provides:
 *
 *   - sm2_sign / sm2_verify  (struct-based, avoids DER encoding)
 *   - sm2_sign_der / sm2_verify_der  (DER-encoded output/input)
 *   - sm2_enc / sm2_dec      (one-shot ECIES with DER framing)
 */
#ifdef NEXTSSL_HAS_GMSSL

#include "sm2.h"
#include <string.h>

/* ---- Sign / Verify ------------------------------------------------------- */

int sm2_sign(const SM2_KEY *key,
             const uint8_t dgst[SM2_DIGEST_SIZE],
             SM2_SIGNATURE *sig)
{
    if (!key || !dgst || !sig) return 0;
    return sm2_do_sign(key, dgst, sig) == 1 ? 1 : 0;
}

int sm2_verify(const SM2_KEY *key,
               const uint8_t dgst[SM2_DIGEST_SIZE],
               const SM2_SIGNATURE *sig)
{
    if (!key || !dgst || !sig) return 0;
    return sm2_do_verify(key, dgst, sig) == 1 ? 1 : 0;
}

int sm2_sign_der(const SM2_KEY *key,
                 const uint8_t dgst[SM2_DIGEST_SIZE],
                 uint8_t *out, size_t *out_len)
{
    if (!key || !dgst || !out || !out_len) return 0;
    if (*out_len < SM2_SIGNATURE_MAX_SIZE) return 0;

    SM2_SIGNATURE sig;
    if (sm2_do_sign(key, dgst, &sig) != 1) return 0;

    /* GmSSL DER-encode: pass a mutable pointer so sm2_signature_to_der
     * advances it; we compute written bytes from the difference. */
    uint8_t *p = out;
    if (sm2_signature_to_der(&sig, &p, out_len) != 1) return 0;
    return 1;
}

int sm2_verify_der(const SM2_KEY *key,
                   const uint8_t dgst[SM2_DIGEST_SIZE],
                   const uint8_t *sig, size_t sig_len)
{
    if (!key || !dgst || !sig || sig_len == 0) return 0;

    SM2_SIGNATURE s;
    const uint8_t *p = sig;
    if (sm2_signature_from_der(&s, &p, &sig_len) != 1) return 0;
    return sm2_do_verify(key, dgst, &s) == 1 ? 1 : 0;
}

/* ---- Encrypt / Decrypt --------------------------------------------------- */

int sm2_enc(const SM2_KEY *key,
            const uint8_t *in, size_t inlen,
            uint8_t *out, size_t *outlen)
{
    if (!key || !in || !out || !outlen) return 0;
    return sm2_encrypt(key, in, inlen, out, outlen) == 1 ? 1 : 0;
}

int sm2_dec(const SM2_KEY *key,
            const uint8_t *in, size_t inlen,
            uint8_t *out, size_t *outlen)
{
    if (!key || !in || !out || !outlen) return 0;
    return sm2_decrypt(key, in, inlen, out, outlen) == 1 ? 1 : 0;
}

#endif /* NEXTSSL_HAS_GMSSL */
