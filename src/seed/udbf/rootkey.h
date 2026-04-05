/**
 * rootkey.h — Domain-separated root-key derivation shim
 *
 * Maps rootkey_get() to HKDF-SHA256 with the algorithm label as the
 * info/context field for domain separation.  Produces independent key
 * streams for distinct (mode, label) pairs even when the same coin
 * bytes are supplied.
 */
#ifndef ROOTKEY_H
#define ROOTKEY_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "../../pqc/common/hkdf/hkdf.h"

/* Derivation mode tags */
typedef enum {
    ROOTKEY_MODE_SEED  = 0,   /* derive a DRBG seed  */
    ROOTKEY_MODE_KEY   = 1,   /* derive a signing key */
    ROOTKEY_MODE_NONCE = 2    /* derive a nonce       */
} rootkey_mode_t;

/**
 * rootkey_get() — derive @out_len bytes into @out using HKDF-SHA256.
 *
 * @mode     : derivation purpose (used as an extra domain-separation byte)
 * @label    : algorithm / operation label (NUL-terminated C string)
 * @ikm      : input key material (coins or entropy)
 * @ikm_len  : length of @ikm in bytes
 * @out      : output buffer
 * @out_len  : requested output length in bytes (≤ 255 * 32)
 */
static inline void rootkey_get(int mode,
                                const char *label,
                                const uint8_t *ikm, size_t ikm_len,
                                uint8_t *out, size_t out_len)
{
    /* Build info = <mode_byte> || <label_bytes> for domain separation */
    size_t label_len = label ? strlen(label) : 0;
    size_t info_len  = 1 + label_len;
    uint8_t info[256];
    if (info_len > sizeof(info)) info_len = sizeof(info);
    info[0] = (uint8_t)(mode & 0xFF);
    if (label_len > 0 && info_len > 1)
        memcpy(info + 1, label, info_len - 1);

    /* HKDF-SHA256: no salt (use zero-filled default inside hkdf) */
    hkdf(NULL, 0, ikm, ikm_len, info, info_len, out, out_len);
}

#endif /* ROOTKEY_H */
