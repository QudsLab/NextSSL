#include "base64.h"

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int radix_base64_encode(const uint8_t *input, size_t input_len,
                        char *output, size_t output_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    size_t required = radix_base64_encoded_size(input_len) + 1;
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
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
    
    if (input_len % 4 != 0) return RADIX_ERROR_INVALID_PADDING;
    
    size_t padding = 0;
    if (input_len > 0) {
        if (input[input_len - 1] == '=') padding++;
        if (input_len > 1 && input[input_len - 2] == '=') padding++;
    }
    
    if (padding > 2) return RADIX_ERROR_INVALID_PADDING; // "===" is not valid
    
    size_t required = (input_len / 4) * 3 - padding;
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
    size_t i = 0, j = 0;
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
        
        // Output bytes
        // If padding=0, 3 bytes
        // If padding=1, 2 bytes
        // If padding=2, 1 byte
        
        if (j < output_len) output[j++] = (val >> 16) & 0xFF;
        if (block_padding < 2 && j < output_len) output[j++] = (val >> 8) & 0xFF;
        if (block_padding < 1 && j < output_len) output[j++] = val & 0xFF;
        
        i += 4;
    }
    
    if (decoded_len) *decoded_len = j;
    return RADIX_SUCCESS;
}
