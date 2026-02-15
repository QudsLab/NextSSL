#include "base64url.h"

static const char base64url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const int base64url_inv_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
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

size_t base64url_encoded_len(size_t bin_len) {
    size_t len = ((bin_len + 2) / 3) * 4;
    // Remove padding length adjustment
    switch (bin_len % 3) {
        case 1: len -= 2; break;
        case 2: len -= 1; break;
    }
    return len + 1;
}

size_t base64url_decoded_len(size_t b64_len) {
    return (b64_len * 3) / 4;
}

int base64url_encode(const uint8_t *bin, size_t bin_len, char *b64, size_t b64_len) {
    if (b64_len < base64url_encoded_len(bin_len)) return -1;

    size_t i, j;
    for (i = 0, j = 0; i < bin_len; i += 3) {
        uint32_t v = bin[i] << 16;
        if (i + 1 < bin_len) v |= bin[i + 1] << 8;
        if (i + 2 < bin_len) v |= bin[i + 2];

        b64[j++] = base64url_table[(v >> 18) & 0x3F];
        b64[j++] = base64url_table[(v >> 12) & 0x3F];
        if (i + 1 < bin_len) b64[j++] = base64url_table[(v >> 6) & 0x3F];
        if (i + 2 < bin_len) b64[j++] = base64url_table[v & 0x3F];
    }
    b64[j] = '\0';
    return 0;
}

int base64url_decode(const char *b64, size_t b64_len, uint8_t *bin, size_t bin_len) {
    if (bin_len < base64url_decoded_len(b64_len)) return -1;

    size_t i = 0, j = 0;
    while (i < b64_len) {
        int v1 = base64url_inv_table[(unsigned char)b64[i++]];
        int v2 = (i < b64_len) ? base64url_inv_table[(unsigned char)b64[i++]] : -1;
        int v3 = (i < b64_len) ? base64url_inv_table[(unsigned char)b64[i++]] : -1;
        int v4 = (i < b64_len) ? base64url_inv_table[(unsigned char)b64[i++]] : -1;

        // Note: For partial blocks, missing chars are treated as padding (value 0 usually, but here handled by bit shifting logic)
        // Wait, without padding, we need to handle partial groups carefully.
        // Actually, for decode, we need to know where we stop.
        
        if (v1 == -1 || v2 == -1) return -1; // Need at least 2 chars

        uint32_t v = (v1 << 18) | (v2 << 12);
        if (v3 != -1) v |= (v3 << 6);
        if (v4 != -1) v |= v4;

        bin[j++] = (v >> 16) & 0xFF;
        if (v3 != -1) bin[j++] = (v >> 8) & 0xFF;
        if (v4 != -1) bin[j++] = v & 0xFF;
    }
    return (int)j;
}
