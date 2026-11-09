/* Shim (not crypto): XXH3_128bits (= XXH128 with seed 0), written as the canonical 16 bytes (high64 then low64, big-endian). */
#include <string.h>
#include "xxhash.h"

void nextssl__xxh128__shim_hash(const unsigned char *data, size_t len, unsigned char *out) {
    XXH128_hash_t h = XXH3_128bits(data, len);
    XXH128_canonical_t c;
    XXH128_canonicalFromHash(&c, h);
    memcpy(out, c.digest, 16);
}
