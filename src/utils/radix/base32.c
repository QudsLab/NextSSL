#include "base32.h"
#include <ctype.h>

static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int radix_base32_encode(const uint8_t *input, size_t input_len,
                        char *output, size_t output_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    size_t required = radix_base32_encoded_size(input_len) + 1;
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
    size_t i = 0, j = 0;
    while (i < input_len) {
        uint64_t val = 0; // Must be 64-bit to hold 40 bits
        int input_bytes = 0;
        
        // Read up to 5 bytes
        for (int k = 0; k < 5; k++) {
            val <<= 8;
            if (i + k < input_len) {
                val |= input[i + k];
                input_bytes++;
            }
        }
        
        // Pad value to the right (align MSB to bit 39)
        // If we read 1 byte (8 bits), we need to shift left by 32 bits to make it 40 bits?
        // No.
        // 1 byte:  [8 bits data] [32 bits zero] -> 40 bits
        // 2 bytes: [16 bits data] [24 bits zero] -> 40 bits
        // 3 bytes: [24 bits data] [16 bits zero] -> 40 bits
        // 4 bytes: [32 bits data] [8 bits zero] -> 40 bits
        // 5 bytes: [40 bits data] -> 40 bits
        
        val <<= (5 - input_bytes) * 8;
        
        // Determine padding characters
        int pad_chars = 0;
        switch (input_bytes) {
            case 1: pad_chars = 6; break;
            case 2: pad_chars = 4; break;
            case 3: pad_chars = 3; break;
            case 4: pad_chars = 1; break;
            default: pad_chars = 0; break;
        }
        
        // Output 8 characters
        for (int k = 0; k < 8; k++) {
            if (k >= 8 - pad_chars) {
                output[j++] = '=';
            } else {
                // Extract top 5 bits
                // Bit 39-35, 34-30, ...
                // Shift: 35 - 5*k
                uint8_t index = (val >> (35 - 5 * k)) & 0x1F;
                output[j++] = base32_chars[index];
            }
        }
        
        i += 5;
    }
    
    output[j] = '\0';
    return RADIX_SUCCESS;
}

static int base32_char_to_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

int radix_base32_decode(const char *input, size_t input_len,
                        uint8_t *output, size_t output_len,
                        size_t *decoded_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    if (input_len % 8 != 0) return RADIX_ERROR_INVALID_PADDING;
    
    // Count padding
    size_t padding = 0;
    if (input_len > 0) {
        for (size_t i = input_len; i > 0; i--) {
            if (input[i-1] == '=') padding++;
            else break;
        }
    }
    
    // Validate padding count
    // Allowed: 0, 1, 3, 4, 6
    if (padding == 2 || padding == 5 || padding > 6) return RADIX_ERROR_INVALID_PADDING;
    
    size_t required = (input_len / 8) * 5; 
    if (padding == 6) required -= 4;
    else if (padding == 4) required -= 3;
    else if (padding == 3) required -= 2;
    else if (padding == 1) required -= 1;
    
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
    size_t i = 0, j = 0;
    while (i < input_len) {
        uint64_t val = 0; 
        
        for (int k = 0; k < 8; k++) {
            char c = input[i + k];
            
            if (c == '=') {
                val <<= 5;
                continue;
            }
            
            int v = base32_char_to_val(c);
            if (v < 0) return RADIX_ERROR_INVALID_ENCODING;
            
            val = (val << 5) | v;
        }
        
        // Determine output bytes for this block
        int block_padding = 0;
        for (int k=0; k<8; k++) {
            if (input[i+k] == '=') block_padding++;
        }
        
        int output_bytes = 5;
        if (block_padding == 6) output_bytes = 1;
        else if (block_padding == 4) output_bytes = 2;
        else if (block_padding == 3) output_bytes = 3;
        else if (block_padding == 1) output_bytes = 4;
        
        for (int k = 0; k < output_bytes; k++) {
             output[j++] = (uint8_t)((val >> (32 - 8 * k)) & 0xFF);
        }
        
        i += 8;
    }
    
    if (decoded_len) *decoded_len = j;
    return RADIX_SUCCESS;
}
