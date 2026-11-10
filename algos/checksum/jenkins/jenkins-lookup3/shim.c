/* Generated shim (not crypto): calls upstream hashlittle (Bob Jenkins lookup3) with initval 0 and returns the 32-bit
 * result big-endian. */
#include <stddef.h>
#include <stdint.h>

uint32_t hashlittle(const void *key, size_t length, uint32_t initval);

void shim_hash(const unsigned char *data, size_t len, unsigned char *out) {
    uint32_t h = hashlittle(data, len, 0);
    out[0] = (unsigned char)(h >> 24);
    out[1] = (unsigned char)(h >> 16);
    out[2] = (unsigned char)(h >> 8);
    out[3] = (unsigned char)h;
}
