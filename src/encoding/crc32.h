/* crc32.h — CRC-32 (ISO 3309 / IEEE 802.3)
 *
 * Polynomial:  0xEDB88320  (reflected form of 0x04C11DB7)
 * Init value:  0xFFFFFFFF
 * Final XOR:   0xFFFFFFFF
 *
 * Usage (full buffer):
 *   uint32_t crc = crc32_compute(data, len);
 *
 * Usage (streaming):
 *   uint32_t crc = crc32_init();
 *   crc = crc32_update(crc, chunk1, len1);
 *   crc = crc32_update(crc, chunk2, len2);
 *   crc = crc32_final(crc);
 */
#ifndef NEXTSSL_ENCODING_CRC32_H
#define NEXTSSL_ENCODING_CRC32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Return initial CRC-32 accumulator value. */
static inline uint32_t crc32_init(void)  { return 0xFFFFFFFFu; }

/** Finalise: XOR with 0xFFFFFFFF to produce the standard CRC. */
static inline uint32_t crc32_final(uint32_t crc) { return crc ^ 0xFFFFFFFFu; }

/** Feed |len| bytes into the running CRC.  Result passed back to crc32_update
 *  or crc32_final.  May be called with len == 0 (no-op). */
uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len);

/** Convenience: compute CRC-32 of a single buffer. */
uint32_t crc32_compute(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ENCODING_CRC32_H */
