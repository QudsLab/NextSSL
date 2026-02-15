#include "base64.h"

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const int base64_inv_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

size_t base64_encoded_len(size_t bin_len) {
    return ((bin_len + 2) / 3) * 4 + 1;
}

size_t base64_decoded_len(size_t b64_len) {
    return (b64_len / 4) * 3;
}

int base64_encode(const uint8_t *bin, size_t bin_len, char *b64, size_t b64_len) {
    if (b64_len < base64_encoded_len(bin_len)) return -1;

    size_t i, j;
    for (i = 0, j = 0; i < bin_len; i += 3) {
        uint32_t v = bin[i] << 16;
        if (i + 1 < bin_len) v |= bin[i + 1] << 8;
        if (i + 2 < bin_len) v |= bin[i + 2];

        b64[j++] = base64_table[(v >> 18) & 0x3F];
        b64[j++] = base64_table[(v >> 12) & 0x3F];
        b64[j++] = (i + 1 < bin_len) ? base64_table[(v >> 6) & 0x3F] : '=';
        b64[j++] = (i + 2 < bin_len) ? base64_table[v & 0x3F] : '=';
    }
    b64[j] = '\0';
    return 0;
}

int base64_decode(const char *b64, size_t b64_len, uint8_t *bin, size_t bin_len) {
    if (b64_len % 4 != 0) return -1;
    size_t out_len = base64_decoded_len(b64_len);
    if (b64[b64_len - 1] == '=') out_len--;
    if (b64[b64_len - 2] == '=') out_len--;

    if (bin_len < out_len) return -1;

    size_t i, j;
    for (i = 0, j = 0; i < b64_len; i += 4) {
        int v1 = base64_inv_table[(unsigned char)b64[i]];
        int v2 = base64_inv_table[(unsigned char)b64[i + 1]];
        int v3 = base64_inv_table[(unsigned char)b64[i + 2]];
        int v4 = base64_inv_table[(unsigned char)b64[i + 3]];

        if (v1 == -1 || v2 == -1 || 
           (v3 == -1 && b64[i + 2] != '=') || 
           (v4 == -1 && b64[i + 3] != '=')) {
            return -1;
        }

        uint32_t v = (v1 << 18) | (v2 << 12) | ((v3 == -1 ? 0 : v3) << 6) | (v4 == -1 ? 0 : v4);

        bin[j++] = (v >> 16) & 0xFF;
        if (b64[i + 2] != '=') bin[j++] = (v >> 8) & 0xFF;
        if (b64[i + 3] != '=') bin[j++] = v & 0xFF;
    }
    return (int)j;
}
