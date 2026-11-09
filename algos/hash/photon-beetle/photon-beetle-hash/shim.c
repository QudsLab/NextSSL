#include <stddef.h>
#include "photon-beetle.h"

/* NextSSL adapter (not upstream code): fixed-output hash entry point. */
int nextssl__photon_beetle_hash__hash(unsigned char *out, const unsigned char *in, unsigned long long len) {
    return photon_beetle_hash(out, in, len);
}
