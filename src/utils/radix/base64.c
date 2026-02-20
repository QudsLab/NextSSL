#include "base64.h"
#include <stdint.h>
#include <stdlib.h>

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t radix_base64_encoded_size(size_t input_len) {
    return (input_len + 2) / 3 * 4;
}

size_t radix_base64_decoded_size(size_t input_len) {
    return (input_len / 4) * 3;
}

int radix_base64_encode(const uint8_t *input, size_t input_len,
                        char *output, size_t output_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    // if input is NULL but len > 0, invalid. If len is 0, empty string.
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    size_t required = radix_base64_encoded_size(input_len) + 1; // +1 for null terminator
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
    if (input_len == 0) {
        output[0] = '\0';
        return RADIX_SUCCESS;
    }

    size_t i = 0, j = 0;
    while (i < input_len) {
        uint32_t val = (input[i++] << 16);
        int bytes = 1;
        
        if (i < input_len) {
            val |= (input[i++] << 8);
            bytes++;
        }
        if (i < input_len) {
            val |= input[i++];
            bytes++;
        }
        
        output[j++] = base64_chars[(val >> 18) & 0x3F];
        output[j++] = base64_chars[(val >> 12) & 0x3F];
        
        if (bytes > 1) output[j++] = base64_chars[(val >> 6) & 0x3F];
        else output[j++] = '=';
        
        if (bytes > 2) output[j++] = base64_chars[val & 0x3F];
        else output[j++] = '=';
    }
    
    output[j] = '\0';
    return RADIX_SUCCESS;
}

static int base64_char_to_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int radix_base64_decode(const char *input, size_t input_len,
                        uint8_t *output, size_t output_len,
                        size_t *decoded_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    if (input_len == 0) {
        if (decoded_len) *decoded_len = 0;
        return RADIX_SUCCESS;
    }
    
    if (input_len % 4 != 0) return RADIX_ERROR_INVALID_PADDING;
    
    size_t padding = 0;
    if (input_len > 0) {
        if (input[input_len - 1] == '=') padding++;
        if (input_len > 1 && input[input_len - 2] == '=') padding++;
    }
    
    if (padding > 2) return RADIX_ERROR_INVALID_PADDING; 
    
    // Estimate required size (upper bound)
    size_t required = (input_len / 4) * 3;
    if (padding > 0) required -= padding;
    
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
    size_t i = 0, j = 0;
    while (i < input_len) {
        uint32_t val = 0;
        
        for (int k = 0; k < 4; k++) {
            char c = input[i + k];
            if (c == '=') {
                val <<= 6;
                continue;
            }
            int v = base64_char_to_val(c);
            if (v < 0) return RADIX_ERROR_INVALID_ENCODING;
            val = (val << 6) | v;
        }
        
        // Block logic:
        // AAAA -> 3 bytes
        // AAA= -> 2 bytes
        // AA== -> 1 byte
        
        // Since we process 4 chars at a time, we output 3 bytes, UNLESS it's the last block with padding.
        // But decoding logic usually just shifts.
        // val has 24 bits (4 * 6).
        
        output[j++] = (val >> 16) & 0xFF;
        if (j < output_len) output[j++] = (val >> 8) & 0xFF;
        if (j < output_len) output[j++] = val & 0xFF;
        
        // Wait, if padding, we shouldn't write extra bytes.
        // The check j < output_len protects us IF output_len is exactly required.
        // But correct logic should check padding for the last block.
        // Let's rely on output_len check for now or fix it.
        // With padding=1 ("AAA="), we have 18 bits valid -> 2 bytes.
        // With padding=2 ("AA=="), we have 12 bits valid -> 1 byte.
        
        i += 4;
    }
    
    // Fix up actual written length if we wrote too much due to padding?
    // My decode loop above writes 3 bytes per block always if space permits.
    // I should fix the decode loop to handle padding correctly.
    // Re-writing decode loop properly.
    
    // Reset j for proper logic
    j = 0;
    i = 0;
    while (i < input_len) {
        uint32_t val = 0;
        int block_padding = 0;
        
        for (int k = 0; k < 4; k++) {
            char c = input[i + k];
            if (c == '=') {
                block_padding++;
                val <<= 6;
                continue;
            }
            int v = base64_char_to_val(c);
            if (v < 0) return RADIX_ERROR_INVALID_ENCODING;
            val = (val << 6) | v;
        }
        
        output[j++] = (val >> 16) & 0xFF;
        if (block_padding < 2) output[j++] = (val >> 8) & 0xFF;
        if (block_padding < 1) output[j++] = val & 0xFF;
        
        i += 4;
    }
    
    if (decoded_len) *decoded_len = j;
    return RADIX_SUCCESS;
}
