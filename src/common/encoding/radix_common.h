#ifndef RADIX_COMMON_H
#define RADIX_COMMON_H

#include <stddef.h>
#include <stdint.h>

// Error codes (return values for all encoding/decoding functions)
typedef enum {
    RADIX_SUCCESS = 0,
    RADIX_ERROR_INVALID_INPUT = -1,      // NULL pointer or invalid length
    RADIX_ERROR_BUFFER_TOO_SMALL = -2,   // Output buffer insufficient
    RADIX_ERROR_INVALID_ENCODING = -3,   // Invalid character in encoded string
    RADIX_ERROR_INVALID_PADDING = -4,    // Bad padding in base64/base32
    RADIX_ERROR_OVERFLOW = -5,           // Calculation overflow
} RadixError;

// Size calculation helpers (use these to determine output buffer sizes)
size_t radix_base16_encoded_size(size_t input_len);
size_t radix_base16_decoded_size(size_t input_len);

size_t radix_base32_encoded_size(size_t input_len);
size_t radix_base32_decoded_size(size_t input_len);

size_t radix_base58_encoded_size(size_t input_len); // Max possible size
size_t radix_base58_decoded_size(size_t input_len); // Max possible size

size_t radix_base64_encoded_size(size_t input_len);
size_t radix_base64_decoded_size(size_t input_len);

size_t radix_base64url_encoded_size(size_t input_len);
size_t radix_base64url_decoded_size(size_t input_len);

#endif // RADIX_COMMON_H
