/* Generated shim (not crypto): little-endian word marshalling around upstream schedule_key and crypt_block. */
#include <stdint.h>
#include <string.h>
#include "mercy.h"

static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int shim_crypt(int direction, const unsigned char *key, int keylen, const unsigned char *spice, unsigned char *block) {
    uint8_t k[256];
    uint32_t sp[SPICE_SIZE], tx[BLOCK_WORDS];
    int i;
    if (keylen < 1 || keylen > 256) return -1;
    memcpy(k, key, (size_t)keylen);
    for (i = 0; i < SPICE_SIZE; i++)
        sp[i] = (uint32_t)spice[4 * i] | ((uint32_t)spice[4 * i + 1] << 8) | ((uint32_t)spice[4 * i + 2] << 16) | ((uint32_t)spice[4 * i + 3] << 24);
    for (i = 0; i < BLOCK_WORDS; i++)
        tx[i] = (uint32_t)block[4 * i] | ((uint32_t)block[4 * i + 1] << 8) | ((uint32_t)block[4 * i + 2] << 16) | ((uint32_t)block[4 * i + 3] << 24);
    schedule_key(k, keylen);
    crypt_block(direction, sp, tx);
    for (i = 0; i < BLOCK_WORDS; i++) {
        block[4 * i] = (unsigned char)tx[i];
        block[4 * i + 1] = (unsigned char)(tx[i] >> 8);
        block[4 * i + 2] = (unsigned char)(tx[i] >> 16);
        block[4 * i + 3] = (unsigned char)(tx[i] >> 24);
    }
    wipe(k, sizeof k);
    wipe(sp, sizeof sp);
    wipe(tx, sizeof tx);
    return 0;
}
