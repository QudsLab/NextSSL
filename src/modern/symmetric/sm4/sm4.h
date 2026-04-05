/* sm4.h — SM4 block cipher (GB/T 32907-2016)
 *
 * SM4 is the Chinese national standard 128-bit block cipher.
 * Key size: 128 bits (16 bytes).  Block size: 128 bits (16 bytes).
 *
 * Implementation: vendored GmSSL source (Apache-2.0 licence).
 * Guarded by NEXTSSL_HAS_GMSSL.
 *
 * This header provides:
 *   - Core ECB block encrypt/decrypt (sm4_encrypt / sm4_decrypt)
 *   - CBC mode (sm4_cbc_encrypt / sm4_cbc_decrypt)
 *   - CTR mode (sm4_ctr_encrypt — nonce-based, same for enc and dec)
 *
 * For GCM and other full AEAD modes see sm4_gmssl.h directly.
 */
#ifndef SM4_H
#define SM4_H

#include <stddef.h>
#include <stdint.h>
#include "sm4_gmssl.h"  /* SM4_KEY, SM4_BLOCK_SIZE, SM4_KEY_SIZE */

#ifdef __cplusplus
extern "C" {
#endif

#define SM4_KEY_LEN    SM4_KEY_SIZE    /* 16 */
#define SM4_BLOCK_LEN  SM4_BLOCK_SIZE  /* 16 */

/* ---- Key setup ----------------------------------------------------------- */

/** Prepare a key context for encryption. */
static inline void sm4_set_enc_key(SM4_KEY *key, const uint8_t raw[SM4_KEY_LEN])
    { sm4_set_encrypt_key(key, raw); }

/** Prepare a key context for decryption. */
static inline void sm4_set_dec_key(SM4_KEY *key, const uint8_t raw[SM4_KEY_LEN])
    { sm4_set_decrypt_key(key, raw); }

/* ---- ECB ----------------------------------------------------------------- */

/** Encrypt a single 16-byte block. */
static inline void sm4_ecb_encrypt(const SM4_KEY *key,
                                   const uint8_t in[SM4_BLOCK_LEN],
                                   uint8_t out[SM4_BLOCK_LEN])
    { sm4_encrypt(key, in, out); }

/* ---- CBC ----------------------------------------------------------------- */

/**
 * CBC encrypt |nblocks| 16-byte blocks.
 * @param iv  16-byte IV, updated in-place to the final ciphertext block.
 */
static inline void sm4_cbc_enc(const SM4_KEY *key,
                                uint8_t iv[SM4_BLOCK_LEN],
                                const uint8_t *in, size_t nblocks,
                                uint8_t *out)
    { sm4_cbc_encrypt_blocks(key, iv, in, nblocks, out); }

/** CBC decrypt |nblocks| blocks. */
static inline void sm4_cbc_dec(const SM4_KEY *key,
                                uint8_t iv[SM4_BLOCK_LEN],
                                const uint8_t *in, size_t nblocks,
                                uint8_t *out)
    { sm4_cbc_decrypt_blocks(key, iv, in, nblocks, out); }

/* ---- CTR ----------------------------------------------------------------- */

/**
 * CTR mode (GmSSL convention: 128-bit big-endian counter starting at IV).
 * @param ctr  16-byte counter block, updated in-place after the call.
 */
static inline void sm4_ctr_enc(const SM4_KEY *key,
                                uint8_t ctr[SM4_BLOCK_LEN],
                                const uint8_t *in, size_t len,
                                uint8_t *out)
    { sm4_ctr_encrypt(key, ctr, in, len, out); }

#ifdef __cplusplus
}
#endif

#endif /* SM4_H */
