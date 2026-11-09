#include <stddef.h>
#include "xoodyak.h"

/* NextSSL adapter (not upstream code): fixed-output hash entry point. */
int nextssl__xoodyak_hash__hash(unsigned char *out, const unsigned char *in, unsigned long long len) {
    return xoodyak_hash(out, in, len);
}
