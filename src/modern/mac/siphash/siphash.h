#ifndef SIPHASH_H
#define SIPHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Computes a SipHash value
 * 
 * @param in Pointer to input data (read-only)
 * @param inlen Input data length in bytes
 * @param k Pointer to the key data (read-only), must be 16 bytes
 * @param out Pointer to output data (write-only)
 * @param outlen Length of the output in bytes, must be 8 or 16
 * @return int 0 on success
 */
int siphash(const void *in, const size_t inlen, const void *k, uint8_t *out,
            const size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // SIPHASH_H
