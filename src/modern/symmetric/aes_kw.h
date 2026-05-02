#ifndef AES_KW_H
#define AES_KW_H

#include <stddef.h>
#include <stdint.h>

/* AES Key Wrap (SP 800-38F §6.2) — plaintext must be a multiple of 8 bytes, >= 16 bytes */
char AES_KEY_wrap(const uint8_t* kek, const void* secret, const size_t secretLen, void* wrapped);
char AES_KEY_unwrap(const uint8_t* kek, const void* wrapped, const size_t wrapLen, void* secret);

/* AES Key Wrap with Padding (SP 800-38F §6.3)
 * plaintext may be any length >= 1 byte.
 * wrappedLen must point to a size_t that receives the output length.
 * wrapped buffer must be at least ((secretLen + 15) / 8) * 8 + 8 bytes. */
char AES_KWP_wrap  (const uint8_t *kek,
                    const void    *secret,  size_t  secretLen,
                    void          *wrapped, size_t *wrappedLen);

/* Returns M_RESULT_SUCCESS on success; *secretLen is set to actual plaintext length. */
char AES_KWP_unwrap(const uint8_t *kek,
                    const void    *wrapped, size_t  wrapLen,
                    void          *secret,  size_t *secretLen);

#endif

