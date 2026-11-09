#include <stddef.h>
#include "crypto_hash.h"

/* NextSSL adapter (not upstream code): fixed-output hash entry point. */
int nextssl__ascon_hash256__hash(unsigned char *out, const unsigned char *in, unsigned long long len) {
    return crypto_hash(out, in, len);
}
