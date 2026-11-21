/* Shim (not crypto): one-shot wrapper over NewKeySchedule/Encrypt/Decrypt of fealnx.c. The upstream F() and Xor4() return pointers to
 * static buffers, so the Rust side holds a process-wide lock around every call. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "fealnx.h"

int shim_crypt(int enc, int rounds, const unsigned char *key, unsigned long keylen, const unsigned char *in, unsigned char *out) {
    unsigned char kb[16], p[8], c[8];
    KeyScheduleType ks;
    if (keylen != 16 || rounds < 4 || rounds > 64 || (rounds & 1)) return -1;
    memcpy(kb, key, 16);
    memcpy(p, in, 8);
    ks = NewKeySchedule(rounds, kb);
    if (ks == NULL) return -1;
    if (enc) Encrypt(ks, p, c); else Decrypt(ks, p, c);
    memcpy(out, c, 8);
    memset(ks->KSchedule, 0, (size_t)(2 * rounds + 16));
    free(ks);
    memset(kb, 0, sizeof(kb));
    memset(p, 0, sizeof(p));
    memset(c, 0, sizeof(c));
    return 0;
}
