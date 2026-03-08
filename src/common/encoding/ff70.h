#ifndef nextssl_UTILS_ENCODING_FF70_H
#define nextssl_UTILS_ENCODING_FF70_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * FF70 Decoded Frame Structure
 */
typedef struct {
    char header[32];      // Identifier (e.g., "FF1:Key")
    char config[64];      // Config string (e.g., "-&@")
    char meta[128];       // Metadata (e.g., "t:123456")
    uint8_t *payload;     // Decoded binary payload data
    size_t payload_len;   // Length of payload
} ff70_frame_t;

/**
 * Encodes data into FlexFrame-70 format.
 * Format: [Header](Config){Payload|Checksum}[Meta]
 * 
 * @param bin Input binary data
 * @param bin_len Length of input data
 * @param header Type identifier (e.g., "Key"). Optional.
 * @param exclude_chars String of characters to exclude from alphabet (e.g., "&@"). Optional.
 * @param meta Metadata string. Optional.
 * @param out Output buffer.
 * @param out_len Size of output buffer.
 * @return Length of string written (excluding null), or 0 on error/overflow.
 */
size_t ff70_encode(const uint8_t *bin, size_t bin_len, 
                   const char *header, const char *exclude_chars, const char *meta,
                   char *out, size_t out_len);

/**
 * Decodes a FlexFrame-70 string.
 * Validates format and checksum (BLAKE3).
 * 
 * @param ff70_str Input FF70 string.
 * @param frame Output frame structure. payload is allocated and must be freed.
 * @return 0 on success, -1 on format error, -2 on checksum failure, -3 on memory error.
 */
int ff70_decode(const char *ff70_str, ff70_frame_t *frame);

/**
 * Frees the payload buffer within the frame.
 */
void ff70_frame_free(ff70_frame_t *frame);

#ifdef __cplusplus
}
#endif

#endif // nextssl_UTILS_ENCODING_FF70_H
