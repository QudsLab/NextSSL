/* Shim (not crypto): one-shot wrapper over the upstream key setup and block routine. The upstream keeps its key schedule in
 * statics, so the Rust side holds a process-wide lock around every call. FEAL-8: 8-byte key, 8-byte block. */
#include <stdint.h>
#include <string.h>
#include "feal8.h"
extern unsigned int K[16];
extern unsigned int K89, K1011, K1213, K1415;
#undef long
int shim_crypt(int enc, const unsigned char *key, unsigned long keylen, const unsigned char *in, unsigned char *out) {
    unsigned char kb[8], p[8], c[8];
    if (keylen != 8) return -1;
    memcpy(kb, key, 8);
    memcpy(p, in, 8);
    SetKey(kb);
    if (enc) Encrypt(p, c); else Decrypt(p, c);
    memcpy(out, c, 8);
    memset(kb, 0, sizeof(kb));
    memset(p, 0, sizeof(p));
    memset(c, 0, sizeof(c));
    memset(K, 0, sizeof(K));
    K89 = K1011 = K1213 = K1415 = 0;
    return 0;
}
