#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#error "chaskey12.c assumes a little-endian target"
#endif

void subkeys(uint32_t k1[4], uint32_t k2[4], const uint32_t k[4]);
void chaskey(uint8_t *tag, uint32_t taglen, const uint8_t *m, const uint32_t mlen, const uint32_t k[4], const uint32_t k1[4], const uint32_t k2[4]);

static void wipe(void *p, size_t n) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}

/* NextSSL adapter (not upstream code): unify the upstream entry point as
 * tag(key, data, len, out, outlen) -> 0 on success. */
int nextssl__chaskey__tag(const void *key, const void *data, size_t len, void *out, size_t outlen) {
    uint32_t k[4], k1[4], k2[4];
    uint8_t *tmp = NULL;
    const uint8_t *m = (const uint8_t *)data;
    if (outlen < 1 || outlen > 16 || len > 0xFFFFFFFFu) return -1;
    memcpy(k, key, 16);
    subkeys(k1, k2, k);
    if (len != 0 && (((uintptr_t)data) & 3) != 0) {
        /* upstream reads the message as uint32_t words: hand it an aligned copy */
        tmp = (uint8_t *)malloc(len);
        if (tmp == NULL) return -1;
        memcpy(tmp, data, len);
        m = tmp;
    }
    chaskey((uint8_t *)out, (uint32_t)outlen, m, (uint32_t)len, k, k1, k2);
    if (tmp != NULL) { wipe(tmp, len); free(tmp); }
    wipe(k, sizeof k); wipe(k1, sizeof k1); wipe(k2, sizeof k2);
    return 0;
}
