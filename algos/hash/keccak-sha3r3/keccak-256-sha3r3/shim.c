/* NextSSL shim (not crypto, not upstream): one-shot entry for the NIST SHA-3 API `Hash()` of this candidate.
 * ns_hash() forwards to the upstream Hash() and maps its HashReturn to 0 (SUCCESS) / non-zero. ns_max_bits() reports
 * the largest value the upstream's DataLength type can hold, so the Rust glue can reject longer inputs instead of
 * letting the bit length wrap. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "KeccakNISTInterface.h"

int ns_hash(int bits, const unsigned char *data, unsigned long long len_bits, unsigned char *out) {
    /* Some upstreams write more than bits/8 bytes into hashval (e.g. a full internal state); hash into a scratch buffer
     * and copy exactly bits/8 so the caller's buffer is never overrun. */
    BitSequence tmp[256];
    HashReturn rc;
    if (bits <= 0 || bits > 2048 || bits % 8 != 0) return 1;
    memset(tmp, 0, sizeof tmp);
    rc = Hash(bits, (const BitSequence *)data, (DataLength)len_bits, tmp);
    if (rc != SUCCESS) return (int)rc + 1;
    memcpy(out, tmp, (size_t)bits / 8);
    return 0;
}

unsigned long long ns_max_bits(void) {
    if ((DataLength)-1 > (DataLength)0) {
        return (unsigned long long)(DataLength)-1;
    }
    return (unsigned long long)((((DataLength)1 << (sizeof(DataLength) * 8 - 2)) - 1) * 2 + 1);
}
