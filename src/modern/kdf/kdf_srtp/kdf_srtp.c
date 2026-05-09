/* kdf_srtp.c — SRTP Key Derivation (RFC 3711 §4.3.1) */
#include "kdf_srtp.h"
#include "../../symmetric/_aes/aes_core.h"
#include <string.h>

int srtp_kdf(const uint8_t  master_key[16],
              const uint8_t  master_salt[14],
              uint64_t       index,
              uint64_t       kdr,
              uint8_t        label,
              uint8_t       *out,
              size_t         out_len)
{
    if (!master_key || !master_salt || !out || out_len == 0) return -1;

    /* r = (kdr == 0) ? 0 : (index / kdr) */
    uint64_t r = (kdr == 0) ? 0 : (index / kdr);

    /* x = (label << 48) XOR (r << 16) */
    uint64_t x = ((uint64_t)label << 48) ^ (r << 16);

    /* IV = (master_salt || 0x0000) XOR (x || 0x0000) */
    /* master_salt is 14 bytes; full 16-byte IV = salt(14) || 0x00 0x00 */
    uint8_t iv[16] = {0};
    memcpy(iv, master_salt, 14);  /* bytes 0..13 = master_salt */
    /* XOR x into the high 8 bytes of iv (bytes 0..7) */
    for (int i = 0; i < 8; i++)
        iv[i] ^= (uint8_t)(x >> (56 - 8 * i));

    /* AES-CM: output blocks = AES(master_key, IV XOR counter_block) */
    /* counter_block = IV with last 2 bytes replaced by big-endian counter */
    size_t done = 0;
    uint16_t blk_ctr = 0;

    while (done < out_len) {
        uint8_t ctr_block[16];
        memcpy(ctr_block, iv, 16);
        ctr_block[14] ^= (uint8_t)(blk_ctr >> 8);
        ctr_block[15] ^= (uint8_t)(blk_ctr);

        uint8_t keystream[16];
        aes_ecb_encrypt_block(master_key, 128, ctr_block, keystream);

        size_t take = (out_len - done < 16) ? (out_len - done) : 16;
        memcpy(out + done, keystream, take);
        done += take;
        blk_ctr++;
    }
    return 0;
}
