/* aes_pmac.h — AES-PMAC parallelizable MAC (Rogaway 2000 / IEEE P1619.1)
 *
 * PMAC is a parallelizable, nonce-free MAC based on a block cipher.
 * It can authenticate messages of arbitrary length with a single-key AES.
 *
 * Tag size: 16 bytes (128 bits).
 * Key size: 16, 24, or 32 bytes (AES-128/192/256).
 */
#ifndef NEXTSSL_AES_PMAC_H
#define NEXTSSL_AES_PMAC_H

#include <stdint.h>
#include <stddef.h>

#define PMAC_TAG_SIZE   16u
#define PMAC_BLOCK_SIZE 16u

/* One-shot PMAC.
 * key    : AES key (16/24/32 bytes)
 * keylen : key length in bytes
 * msg    : input message
 * msglen : message length (may be 0)
 * tag    : 16-byte output tag
 * Returns 0 on success, -1 on error. */
int aes_pmac(const uint8_t *key,  size_t keylen,
             const uint8_t *msg,  size_t msglen,
             uint8_t        tag[PMAC_TAG_SIZE]);

/* Streaming interface */
typedef struct {
    uint8_t  L[16];        /* L = E_K(0) */
    uint8_t  Lx[16];       /* L[i] = 2*L[i-1] in GF(2^128) */
    uint8_t  sum[16];      /* running XOR sum of block MACs */
    uint8_t  buf[16];      /* incomplete block */
    size_t   buf_len;
    size_t   block_count;  /* number of complete blocks processed */
    uint8_t  key[32];
    size_t   keylen;
} pmac_ctx;

int pmac_init  (pmac_ctx *ctx, const uint8_t *key, size_t keylen);
int pmac_update(pmac_ctx *ctx, const uint8_t *data, size_t len);
int pmac_final (pmac_ctx *ctx, uint8_t tag[PMAC_TAG_SIZE]);

#endif /* NEXTSSL_AES_PMAC_H */
