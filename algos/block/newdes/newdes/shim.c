/* Shim (not crypto): one-shot wrapper over newdes_set_key_encipher/decipher + newdes_block. The upstream keeps the unravelled key in a static
 * array, so the Rust side holds a process-wide lock around every call. */
#include <stdint.h>
#include <string.h>

extern unsigned char newdes_key_unravelled[60];
void newdes_block(unsigned char *block);
void newdes_set_key_encipher(unsigned char *key);
void newdes_set_key_decipher(unsigned char *key);

int shim_crypt(int enc, const unsigned char *key, unsigned long keylen, const unsigned char *in, unsigned char *out) {
    unsigned char kb[15], b[8];
    if (keylen != 15) return -1;
    memcpy(kb, key, 15);
    memcpy(b, in, 8);
    if (enc) newdes_set_key_encipher(kb); else newdes_set_key_decipher(kb);
    newdes_block(b);
    memcpy(out, b, 8);
    memset(kb, 0, sizeof(kb));
    memset(b, 0, sizeof(b));
    memset(newdes_key_unravelled, 0, sizeof(newdes_key_unravelled));
    return 0;
}
