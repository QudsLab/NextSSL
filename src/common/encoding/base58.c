#include "base58.h"
#include <string.h>
#include <stdlib.h> // For malloc/free as fallback

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int radix_base58_encode(const uint8_t *input, size_t input_len,
                        char *output, size_t output_len,
                        size_t *encoded_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    // Count leading zeros
    size_t zeros = 0;
    while (zeros < input_len && input[zeros] == 0) {
        zeros++;
    }
    
    // Allocate buffer for base58 digits
    // Size approx input_len * 138 / 100 + 1
    size_t b58_sz = input_len * 2 + 1; 
    unsigned char *b58 = (unsigned char *)malloc(b58_sz);
    if (!b58) return RADIX_ERROR_INVALID_INPUT; // Allocation failure
    
    memset(b58, 0, b58_sz);
    size_t length = 0;
    
    // Process the bytes
    for (size_t i = zeros; i < input_len; i++) {
        int carry = input[i];
        size_t j = 0;
        
        // Apply "b58 = b58 * 256 + byte"
        for (size_t k = 0; k < length || carry != 0; k++, j++) {
            if (k == length) length++;
            int val = carry + (int)(b58[k]) * 256;
            b58[k] = (unsigned char)(val % 58);
            carry = val / 58;
        }
    }
    
    // Check buffer size
    size_t total_len = zeros + length;
    if (output_len < total_len + 1) {
        free(b58);
        return RADIX_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Output leading '1's
    size_t out_idx = 0;
    for (size_t i = 0; i < zeros; i++) {
        output[out_idx++] = '1';
    }
    
    // Output base58 digits (reversed)
    for (size_t i = 0; i < length; i++) {
        output[out_idx++] = base58_chars[b58[length - 1 - i]];
    }
    
    output[out_idx] = '\0';
    free(b58);
    
    if (encoded_len) *encoded_len = out_idx;
    return RADIX_SUCCESS;
}

static int base58_char_to_val(char c) {
    const char *p = strchr(base58_chars, c);
    if (p) return (int)(p - base58_chars);
    return -1;
}

int radix_base58_decode(const char *input, size_t input_len,
                        uint8_t *output, size_t output_len,
                        size_t *decoded_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    // Skip leading spaces? No, strict mode.
    
    // Count leading '1's
    size_t zeros = 0;
    while (zeros < input_len && input[zeros] == '1') {
        zeros++;
    }
    
    // Allocate buffer for big integer bytes
    // Size approx input_len * 733 / 1000 + 1
    size_t bin_sz = input_len + 1;
    unsigned char *bin = (unsigned char *)malloc(bin_sz);
    if (!bin) return RADIX_ERROR_INVALID_INPUT;
    
    memset(bin, 0, bin_sz);
    size_t length = 0;
    
    // Process base58 digits
    for (size_t i = zeros; i < input_len; i++) {
        int val = base58_char_to_val(input[i]);
        if (val < 0) {
            free(bin);
            return RADIX_ERROR_INVALID_ENCODING;
        }
        
        int carry = val;
        // Apply "bin = bin * 58 + val"
        for (size_t k = 0; k < length || carry != 0; k++) {
            if (k == length) length++;
            int acc = carry + (int)(bin[k]) * 58;
            bin[k] = (unsigned char)(acc % 256);
            carry = acc / 256;
        }
    }
    
    // Check output buffer size
    size_t total_len = zeros + length;
    if (output_len < total_len) {
        free(bin);
        return RADIX_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Output leading zeros
    size_t out_idx = 0;
    memset(output, 0, zeros);
    out_idx = zeros;
    
    // Output bytes (reversed)
    for (size_t i = 0; i < length; i++) {
        output[out_idx++] = bin[length - 1 - i];
    }
    
    free(bin);
    
    if (decoded_len) *decoded_len = out_idx;
    return RADIX_SUCCESS;
}
