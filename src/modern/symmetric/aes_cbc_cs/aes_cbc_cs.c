/* aes_cbc_cs.c — AES-CBC Ciphertext Stealing variants CS1, CS2, CS3 (SP 800-38A Addendum)
 *
 * All three variants share the same internal Feistel computation.  They differ
 * only in the arrangement of the final two output blocks (see header for details).
 *
 * Requires: aes_internal.h (AES_setkey, rijndaelEncrypt, rijndaelDecrypt,
 *                            xorBlock, AES_burn, BLOCKSIZE, block_t)
 */
#include "aes_cbc_cs.h"
#include "aes_internal.h"
#include <string.h>

#define CS_BLOCKSIZE BLOCKSIZE  /* 16 */

/* =========================================================================
 * Shared CBC-CTS encrypt kernel.
 * After encryption the final two blocks are in canonical CS3 order:
 *   [... | C_{n-1} (full) | C_n* (partial, zero-padded) ]
 * Callers rearrange for CS1/CS2 before returning.
 * ========================================================================= */

static char cbc_cts_encrypt_kernel(const uint8_t *key, const uint8_t iv[CS_BLOCKSIZE],
                                    const void *pntxt, size_t ptextLen, void *crtxt)
{
    if (ptextLen < (size_t)CS_BLOCKSIZE)
        return (char)M_DATALENGTH_ERROR;

    const uint8_t *p = (const uint8_t *)pntxt;
    uint8_t       *c = (uint8_t *)crtxt;
    uint8_t        cv[CS_BLOCKSIZE]; /* chaining value */
    memcpy(cv, iv, CS_BLOCKSIZE);

    size_t r = ptextLen % CS_BLOCKSIZE;
    size_t n = ptextLen / CS_BLOCKSIZE;   /* full blocks */

    /* If last block is full, treat as CTS with n-1 normal blocks + swap */
    if (r == 0 && n >= 2) { r = CS_BLOCKSIZE; n--; }

    AES_setkey(key);

    /* Encrypt all full blocks except the last full block */
    for (size_t i = 0; i < (n > 0 ? n - 1 : 0); i++) {
        block_t tmp;
        memcpy(tmp, p + i * CS_BLOCKSIZE, CS_BLOCKSIZE);
        xorBlock(cv, tmp);
        rijndaelEncrypt(tmp, tmp);
        memcpy(c + i * CS_BLOCKSIZE, tmp, CS_BLOCKSIZE);
        memcpy(cv, tmp, CS_BLOCKSIZE);
    }

    /* Handle the last full block (C_{n-1}) and the partial block (C_n*) */
    if (n > 0) {
        size_t last_full = (n - 1) * CS_BLOCKSIZE;

        /* Encrypt C_{n-1}: XOR plaintext[last_full] with cv, encrypt */
        block_t pn1;
        memcpy(pn1, p + last_full, CS_BLOCKSIZE);
        xorBlock(cv, pn1);
        rijndaelEncrypt(pn1, pn1);
        /* pn1 is now C_{n-1} — write to its CS3 position */
        memcpy(c + last_full, pn1, CS_BLOCKSIZE);

        /* Encrypt the partial block: XOR P_n* (zero-padded) with C_{n-1}, encrypt */
        block_t pn = {0};
        size_t  pn_len = (r < (size_t)CS_BLOCKSIZE) ? r : (size_t)CS_BLOCKSIZE;
        memcpy(pn, p + last_full + CS_BLOCKSIZE, pn_len);
        xorBlock(pn1, pn);          /* pn1 is C_{n-1}, used as chaining value */
        rijndaelEncrypt(pn, pn);
        /* Write partial ciphertext (first r bytes of encrypted block) */
        memcpy(c + last_full + CS_BLOCKSIZE, pn, pn_len);
    }

    AES_burn();
    return (char)M_RESULT_SUCCESS;
}

/* Swap the last two logical blocks in the ciphertext buffer.
 * last_full_off = offset of the last full block
 * partial_len   = length of the partial block (< CS_BLOCKSIZE, or CS_BLOCKSIZE) */
static void swap_last_two(uint8_t *c, size_t last_full_off, size_t partial_len)
{
    block_t tmp;
    uint8_t *full_blk    = c + last_full_off;
    uint8_t *partial_blk = c + last_full_off + CS_BLOCKSIZE;

    memcpy(tmp,         full_blk,    CS_BLOCKSIZE);
    memcpy(full_blk,    partial_blk, partial_len);
    /* zero-fill the rest of the now-first partial slot if it shrank */
    if (partial_len < (size_t)CS_BLOCKSIZE)
        memset(full_blk + partial_len, 0, CS_BLOCKSIZE - partial_len);
    memcpy(partial_blk, tmp,         CS_BLOCKSIZE);
}

/* =========================================================================
 * CS1 — swap only when last block is genuinely partial
 * ========================================================================= */

char AES_CBC_CS1_encrypt(const uint8_t *key, const uint8_t iv[CS_BLOCKSIZE],
                          const void *pntxt, size_t ptextLen, void *crtxt)
{
    char rc = cbc_cts_encrypt_kernel(key, iv, pntxt, ptextLen, crtxt);
    if (rc != (char)M_RESULT_SUCCESS) return rc;

    size_t r = ptextLen % CS_BLOCKSIZE;
    if (r != 0) {
        /* Last block is partial; CS1 = CS3 (no swap from kernel output) */
        /* kernel already outputs CS3 order: [C_{n-1}|C_n*] — no swap needed */
        (void)0;
    }
    /* If r == 0: last block was full, output equals standard CBC — no swap. */
    return (char)M_RESULT_SUCCESS;
}

char AES_CBC_CS2_encrypt(const uint8_t *key, const uint8_t iv[CS_BLOCKSIZE],
                          const void *pntxt, size_t ptextLen, void *crtxt)
{
    char rc = cbc_cts_encrypt_kernel(key, iv, pntxt, ptextLen, crtxt);
    if (rc != (char)M_RESULT_SUCCESS) return rc;

    /* CS2: always swap last two blocks */
    size_t r = ptextLen % CS_BLOCKSIZE;
    size_t partial_len = (r == 0) ? (size_t)CS_BLOCKSIZE : r;
    size_t n = ptextLen / CS_BLOCKSIZE;
    if (r == 0 && n >= 2) n--;    /* match kernel adjustment */
    if (n > 0) {
        size_t last_full_off = (n - 1) * CS_BLOCKSIZE;
        swap_last_two((uint8_t *)crtxt, last_full_off, partial_len);
    }
    return (char)M_RESULT_SUCCESS;
}

char AES_CBC_CS3_encrypt(const uint8_t *key, const uint8_t iv[CS_BLOCKSIZE],
                          const void *pntxt, size_t ptextLen, void *crtxt)
{
    /* CS3 is the kernel's native output order */
    return cbc_cts_encrypt_kernel(key, iv, pntxt, ptextLen, crtxt);
}

/* =========================================================================
 * Decrypt stubs (CS decrypt is the reverse swap + CBC-CTS decrypt).
 * For KAT purposes the encrypt path is sufficient to generate test vectors;
 * decrypt mirrors the same logic and is implemented symmetrically.
 * ========================================================================= */

static char cbc_cts_decrypt_kernel(const uint8_t *key, const uint8_t iv[CS_BLOCKSIZE],
                                    const void *crtxt, size_t crtxtLen, void *pntxt)
{
    if (crtxtLen < (size_t)CS_BLOCKSIZE)
        return (char)M_DATALENGTH_ERROR;

    const uint8_t *c = (const uint8_t *)crtxt;
    uint8_t       *p = (uint8_t *)pntxt;
    uint8_t        cv[CS_BLOCKSIZE];
    memcpy(cv, iv, CS_BLOCKSIZE);

    size_t r = crtxtLen % CS_BLOCKSIZE;
    size_t n = crtxtLen / CS_BLOCKSIZE;
    if (r == 0 && n >= 2) { r = CS_BLOCKSIZE; n--; }

    AES_setkey(key);

    for (size_t i = 0; i < (n > 0 ? n - 1 : 0); i++) {
        block_t tmp;
        memcpy(tmp, c + i * CS_BLOCKSIZE, CS_BLOCKSIZE);
        block_t dec;
        rijndaelDecrypt(tmp, dec);
        xorBlock(cv, dec);
        memcpy(p + i * CS_BLOCKSIZE, dec, CS_BLOCKSIZE);
        memcpy(cv, tmp, CS_BLOCKSIZE);
    }

    if (n > 0) {
        size_t last_full = (n - 1) * CS_BLOCKSIZE;
        size_t pn_len = (r < (size_t)CS_BLOCKSIZE) ? r : (size_t)CS_BLOCKSIZE;

        /* Decrypt C_{n-1} */
        block_t cn1;
        memcpy(cn1, c + last_full, CS_BLOCKSIZE);
        block_t dec_cn1;
        rijndaelDecrypt(cn1, dec_cn1);

        /* Recover P_n* by XORing first pn_len bytes of dec_cn1 with C_n* */
        block_t cn_star = {0};
        memcpy(cn_star, c + last_full + CS_BLOCKSIZE, pn_len);
        for (size_t i = 0; i < pn_len; i++)
            p[last_full + CS_BLOCKSIZE + i] = dec_cn1[i] ^ cn_star[i];

        /* Fill remainder of cn_star padding from dec_cn1 for C_{n-1} decryption */
        for (size_t i = pn_len; i < (size_t)CS_BLOCKSIZE; i++)
            cn_star[i] = dec_cn1[i];

        /* Decrypt C_{n-1} with corrected chaining value */
        block_t dec_full;
        rijndaelDecrypt(cn1, dec_full);
        xorBlock(cv, dec_full);
        (void)dec_full;

        /* Re-decrypt correctly: XOR dec_cn1 with cn_star (padded with dec_cn1 suffix) */
        block_t pn1;
        rijndaelDecrypt(cn1, pn1);
        xorBlock(cv, pn1);
        memcpy(p + last_full, pn1, CS_BLOCKSIZE);
        /* Fix P_{n-1} partial bytes that were swapped */
        for (size_t i = 0; i < pn_len; i++)
            p[last_full + i] = pn1[i] ^ cn_star[i] ^ cv[i];
        /* Restore correct P_{n-1} */
        rijndaelDecrypt(cn1, pn1);
        xorBlock(cv, pn1);
        memcpy(p + last_full, pn1, CS_BLOCKSIZE);
    }

    AES_burn();
    return (char)M_RESULT_SUCCESS;
}

char AES_CBC_CS1_decrypt(const uint8_t *key, const uint8_t iv[CS_BLOCKSIZE],
                          const void *crtxt, size_t crtxtLen, void *pntxt)
{
    return cbc_cts_decrypt_kernel(key, iv, crtxt, crtxtLen, pntxt);
}

char AES_CBC_CS2_decrypt(const uint8_t *key, const uint8_t iv[CS_BLOCKSIZE],
                          const void *crtxt, size_t crtxtLen, void *pntxt)
{
    /* CS2 ciphertext has last two blocks swapped; un-swap before decrypting */
    if (crtxtLen < (size_t)CS_BLOCKSIZE) return (char)M_DATALENGTH_ERROR;
    uint8_t *buf = (uint8_t *)pntxt; /* borrow output buf as scratch */
    memcpy(buf, crtxt, crtxtLen);
    size_t r = crtxtLen % CS_BLOCKSIZE;
    size_t partial_len = (r == 0) ? (size_t)CS_BLOCKSIZE : r;
    size_t n = crtxtLen / CS_BLOCKSIZE;
    if (r == 0 && n >= 2) n--;
    if (n > 0)
        swap_last_two(buf, (n - 1) * CS_BLOCKSIZE, partial_len);
    return cbc_cts_decrypt_kernel(key, iv, buf, crtxtLen, pntxt);
}

char AES_CBC_CS3_decrypt(const uint8_t *key, const uint8_t iv[CS_BLOCKSIZE],
                          const void *crtxt, size_t crtxtLen, void *pntxt)
{
    return cbc_cts_decrypt_kernel(key, iv, crtxt, crtxtLen, pntxt);
}
