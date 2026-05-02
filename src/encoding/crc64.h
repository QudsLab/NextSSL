/* crc64.h — CRC-64 ECMA-182
 *
 * Polynomial: 0xC96C5795D7870F42 (reflected form of the ECMA-182 poly)
 * Init value: 0xFFFFFFFFFFFFFFFF
 * Final XOR:  0xFFFFFFFFFFFFFFFF
 *
 * This is the variant used by XZ/LZMA, SCTP, and disk sector formats.
 *
 * Usage (full buffer):
 *   uint64_t crc = crc64_compute(data, len);
 *
 * Usage (streaming):
 *   uint64_t crc = crc64_init();
 *   crc = crc64_update(crc, chunk1, len1);
 *   crc = crc64_update(crc, chunk2, len2);
 *   crc = crc64_final(crc);
 */
#ifndef NEXTSSL_ENCODING_CRC64_H
#define NEXTSSL_ENCODING_CRC64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t crc64_init(void)             { return UINT64_C(0xFFFFFFFFFFFFFFFF); }
static inline uint64_t crc64_final(uint64_t crc)    { return crc ^ UINT64_C(0xFFFFFFFFFFFFFFFF); }

uint64_t crc64_update(uint64_t crc, const uint8_t *data, size_t len);
uint64_t crc64_compute(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ENCODING_CRC64_H */
