#include "hex.h"
#include <ctype.h>

static const char hex_table[] = "0123456789abcdef";

size_t hex_encoded_len(size_t bin_len) {
    return bin_len * 2 + 1;
}

size_t hex_decoded_len(size_t hex_len) {
    return hex_len / 2;
}

int hex_encode(const uint8_t *bin, size_t bin_len, char *hex, size_t hex_len) {
    if (hex_len < hex_encoded_len(bin_len)) {
        return -1;
    }

    for (size_t i = 0; i < bin_len; ++i) {
        hex[i * 2] = hex_table[(bin[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_table[bin[i] & 0x0F];
    }
    hex[bin_len * 2] = '\0';
    return 0;
}

static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(const char *hex, size_t hex_len, uint8_t *bin, size_t bin_len) {
    if (hex_len % 2 != 0) {
        return -1; // Must be even length
    }
    if (bin_len < hex_len / 2) {
        return -1;
    }

    for (size_t i = 0; i < hex_len / 2; ++i) {
        int hi = hex_char_to_int(hex[i * 2]);
        int lo = hex_char_to_int(hex[i * 2 + 1]);

        if (hi == -1 || lo == -1) {
            return -1; // Invalid character
        }

        bin[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
