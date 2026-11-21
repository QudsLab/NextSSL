/* Shim (not crypto): one-shot wrapper over the upstream key setup and block routine. The upstream keeps its key schedule in
 * statics, so the Rust side holds a process-wide lock around every call. Block = 8 bytes as upstream's char[8] (big-endian halves: upstream byte-swaps on LITTLE_ENDIAN). */
#include <stdint.h>
#include <string.h>
#include "loki.h"
extern Long loki_subkeys[ROUNDS];
#undef long
int shim_crypt(int enc, const unsigned char *key, unsigned long keylen, const unsigned char *in, unsigned char *out) {
    char kb[8], bb[8];
    if (keylen != 8) return -1;
    memcpy(kb, key, 8);
    memcpy(bb, in, 8);
    setlokikey(kb);
    if (enc) enloki(bb); else deloki(bb);
    memcpy(out, bb, 8);
    memset(kb, 0, sizeof(kb));
    memset(bb, 0, sizeof(bb));
    memset(lokikey, 0, sizeof(lokikey));
    return 0;
}
