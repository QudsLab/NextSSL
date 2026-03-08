#include "radix_common.h"

// Base16: 1 byte → 2 hex chars
size_t radix_base16_encoded_size(size_t input_len) {
    return input_len * 2;
}

size_t radix_base16_decoded_size(size_t input_len) {
    return input_len / 2;
}

// Base32: 5 bytes → 8 chars (with padding)
size_t radix_base32_encoded_size(size_t input_len) {
    return ((input_len + 4) / 5) * 8;
}

size_t radix_base32_decoded_size(size_t input_len) {
    return (input_len / 8) * 5;
}

// Base58: Variable (no padding), estimate max size
size_t radix_base58_encoded_size(size_t input_len) {
    // Max size: log_58(256) * input_len ≈ 1.37 * input_len
    return input_len * 2; // Safe upper bound
}

size_t radix_base58_decoded_size(size_t input_len) {
    // Max decoded size
    return input_len; // Safe upper bound
}

// Base64: 3 bytes → 4 chars (with padding)
size_t radix_base64_encoded_size(size_t input_len) {
    return ((input_len + 2) / 3) * 4;
}

size_t radix_base64_decoded_size(size_t input_len) {
    return (input_len / 4) * 3;
}

// Base64URL: Same as Base64
size_t radix_base64url_encoded_size(size_t input_len) {
    return radix_base64_encoded_size(input_len);
}

size_t radix_base64url_decoded_size(size_t input_len) {
    return radix_base64_decoded_size(input_len);
}
