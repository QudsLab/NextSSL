#include <stddef.h>
#include <stdint.h>
#include "md6.h"

/* NextSSL adapter (not upstream code): one-shot MD6 with d = 8 * out_len bits (out_len 1..=64). */
int nextssl__md6__digest(unsigned out_len, const void *data, size_t len, void *out) {
    if (out_len < 1 || out_len > 64) return -1;
    return md6_hash((int)(8 * out_len), (unsigned char *)data, (uint64_t)len * 8, (unsigned char *)out) == 0 ? 0 : -1;
}
