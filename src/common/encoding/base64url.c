#include "base64url.h"
#include "base64.h" // Reuse base64 encode logic if possible, or reimplement?
// Base64URL uses different alphabet. Reimplementing is cleaner to avoid modifying base64 output.

static const char base64url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int radix_base64url_encode(const uint8_t *input, size_t input_len,
                           char *output, size_t output_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    size_t required = radix_base64url_encoded_size(input_len) + 1;
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
        
        output[j++] = base64url_chars[(val >> 18) & 0x3F];
        output[j++] = base64url_chars[(val >> 12) & 0x3F];
        
        if (bytes > 1) output[j++] = base64url_chars[(val >> 6) & 0x3F];
        else output[j++] = '=';
        
        if (bytes > 2) output[j++] = base64url_chars[val & 0x3F];
        else output[j++] = '=';
    }
    
    output[j] = '\0';
    return RADIX_SUCCESS;
}

int radix_base64url_encode_nopad(const uint8_t *input, size_t input_len,
                                 char *output, size_t output_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    // Calculate size without padding
    size_t padded_size = radix_base64url_encoded_size(input_len);
    size_t padding = 0;
    if (input_len % 3 == 1) padding = 2;
    else if (input_len % 3 == 2) padding = 1;
    
    size_t required = padded_size - padding + 1;
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
        
        output[j++] = base64url_chars[(val >> 18) & 0x3F];
        output[j++] = base64url_chars[(val >> 12) & 0x3F];
        
        if (bytes > 1) output[j++] = base64url_chars[(val >> 6) & 0x3F];
        if (bytes > 2) output[j++] = base64url_chars[val & 0x3F];
    }
    
    output[j] = '\0';
    return RADIX_SUCCESS;
}

static int base64url_char_to_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int radix_base64url_decode(const char *input, size_t input_len,
                           uint8_t *output, size_t output_len,
                           size_t *decoded_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    // Handle optional padding
    // If input has padding, verify length % 4 == 0
    // If input has no padding, we need to treat it as partial block
    
    size_t padding = 0;
    if (input_len > 0 && input[input_len - 1] == '=') {
        if (input_len % 4 != 0) return RADIX_ERROR_INVALID_PADDING;
        padding++;
        if (input_len > 1 && input[input_len - 2] == '=') padding++;
    } else {
        // No padding in input string
        // Calculate implicit padding based on length % 4
        size_t rem = input_len % 4;
        if (rem == 2) padding = 2; // 2 chars -> need 2 pads
        else if (rem == 3) padding = 1; // 3 chars -> need 1 pad
        else if (rem == 0) padding = 0; // 0 or 4 chars -> 0 pads
        else return RADIX_ERROR_INVALID_ENCODING; // 1 char is invalid
    }
    
    // Validate output size
    size_t full_blocks = (input_len + padding) / 4;
    size_t required = full_blocks * 3 - padding;
    
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
    size_t i = 0, j = 0;
    while (i < input_len) {
        uint32_t val = 0;
        int chars_processed = 0;
        
        for (int k = 0; k < 4; k++) {
            if (i + k >= input_len) {
                // Implicit padding
                val <<= 6;
                continue;
            }
            
            char c = input[i + k];
            if (c == '=') {
                val <<= 6;
                continue;
            }
            
            int v = base64url_char_to_val(c);
            if (v < 0) return RADIX_ERROR_INVALID_ENCODING;
            val = (val << 6) | v;
            chars_processed++;
        }
        
        // Output bytes
        // Logic same as base64, but handling implicit padding
        // If we processed 4 chars (0 pad), 3 bytes
        // If we processed 3 chars (1 pad), 2 bytes
        // If we processed 2 chars (2 pad), 1 byte
        
        // Determine actual padding for this block
        // If i + 4 > input_len, implicit padding
        // Or explicit '='
        
        int block_pad = 0;
        if (i + 4 > input_len) {
            block_pad = 4 - (input_len - i);
        } else {
            for (int k=0; k<4; k++) if (input[i+k] == '=') block_pad++;
        }
        
        if (j < output_len) output[j++] = (val >> 16) & 0xFF;
        if (block_pad < 2 && j < output_len) output[j++] = (val >> 8) & 0xFF;
        if (block_pad < 1 && j < output_len) output[j++] = val & 0xFF;
        
        i += 4;
    }
    
    if (decoded_len) *decoded_len = j;
    return RADIX_SUCCESS;
}
