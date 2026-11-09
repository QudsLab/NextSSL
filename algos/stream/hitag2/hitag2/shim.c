/* NextSSL adapter (not upstream code): maps the byte arguments to the integers the ported functions take
 * (big-endian: key = 6 bytes, uid = nonce[0..3], nonce = nonce[4..7]) and XORs the keystream into the data. */
#include <stddef.h>
#include <stdint.h>
#include "hitag2.h"

static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

int shim_apply(const unsigned char *key, const unsigned char *nonce, unsigned char *data, size_t len) {
    uint64_t k = 0, state;
    uint32_t uid = 0, nn = 0;
    uint8_t ks[64];
    size_t off, n, i;
    int j;
    for (j = 0; j < 6; j++) k = (k << 8) | key[j];
    for (j = 0; j < 4; j++) uid = (uid << 8) | nonce[j];
    for (j = 4; j < 8; j++) nn = (nn << 8) | nonce[j];
    state = hitag2_init(k, uid, nn);
    for (off = 0; off < len; off += n) {
        n = len - off < sizeof ks ? len - off : sizeof ks;
        hitag2_keystream(&state, ks, 8 * n);
        for (i = 0; i < n; i++) data[off + i] ^= ks[i];
    }
    wipe(ks, sizeof ks);
    wipe(&state, sizeof state);
    wipe(&k, sizeof k);
    return 0;
}
