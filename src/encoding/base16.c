#include "base16.h"

static const char hex_lower[] = "0123456789abcdef";
static const char hex_upper[] = "0123456789ABCDEF";

int radix_base16_encode(const uint8_t *input, size_t input_len,
                        char *output, size_t output_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    size_t required = radix_base16_encoded_size(input_len) + 1;
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
    for (size_t i = 0; i < input_len; i++) {
        output[i * 2] = hex_lower[(input[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex_lower[input[i] & 0x0F];
    }
    
    output[input_len * 2] = '\0';
    return RADIX_SUCCESS;
}

int radix_base16_encode_upper(const uint8_t *input, size_t input_len,
                              char *output, size_t output_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    size_t required = radix_base16_encoded_size(input_len) + 1;
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
    for (size_t i = 0; i < input_len; i++) {
        output[i * 2] = hex_upper[(input[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex_upper[input[i] & 0x0F];
    }
    
    output[input_len * 2] = '\0';
    return RADIX_SUCCESS;
}

static int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int radix_base16_decode(const char *input, size_t input_len,
                        uint8_t *output, size_t output_len,
                        size_t *decoded_len) {
    if (output == NULL) return RADIX_ERROR_INVALID_INPUT;
    if (input == NULL && input_len > 0) return RADIX_ERROR_INVALID_INPUT;
    
    if (input_len % 2 != 0) return RADIX_ERROR_INVALID_ENCODING;
    
    size_t required = radix_base16_decoded_size(input_len);
    if (output_len < required) return RADIX_ERROR_BUFFER_TOO_SMALL;
    
    for (size_t i = 0; i < required; i++) {
        int high = hex_char_to_val(input[i * 2]);
        int low = hex_char_to_val(input[i * 2 + 1]);
        
        if (high < 0 || low < 0) return RADIX_ERROR_INVALID_ENCODING;
        
        output[i] = (uint8_t)((high << 4) | low);
    }
    
    if (decoded_len) *decoded_len = required;
    return RADIX_SUCCESS;
}
