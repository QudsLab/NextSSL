#include "ff70.h"
#include "../../primitives/hash/fast/blake3/blake3.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Full 70-char Super Set
// 0-9 (10) + a-z (26) + A-Z (26) + specials (8) = 70
static const char FF70_SUPER_SET[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%&;:|";
static const size_t FF70_FULL_BASE = 70;

#define DEFAULT_SEPARATOR '|'
#define CHECKSUM_SIZE 4 // 4 bytes of Blake3

// Helper: Check if char is in string
static int char_in_str(char c, const char *str) {
    if (!str) return 0;
    while (*str) {
        if (*str == c) return 1;
        str++;
    }
    return 0;
}

// Helper: Build alphabet based on exclusions and separator
// Returns base
static size_t build_alphabet(const char *exclude, char separator, char *out_alphabet) {
    size_t base = 0;
    for (size_t i = 0; i < FF70_FULL_BASE; i++) {
        char c = FF70_SUPER_SET[i];
        // Exclude if explicitly excluded OR if it is the separator
        if (c == separator || char_in_str(c, exclude)) {
            continue;
        }
        out_alphabet[base++] = c;
    }
    out_alphabet[base] = '\0';
    return base;
}

// Helper: Inverse alphabet lookup
static int get_char_value(char c, const char *alphabet) {
    const char *p = strchr(alphabet, c);
    if (p) return (int)(p - alphabet);
    return -1;
}

// Helper: BaseN Encode (BigInt division)
// out_str must be large enough. Returns length.
static size_t base_n_encode(const uint8_t *in, size_t in_len, const char *alphabet, size_t base, char *out_str) {
    if (in_len == 0) return 0;
    
    // Copy input to temporary buffer for modification (division)
    uint8_t *tmp = (uint8_t *)malloc(in_len);
    if (!tmp) return 0;
    memcpy(tmp, in, in_len);

    char *ptr = out_str;
    
    // While number > 0
    int non_zero = 1;
    while (non_zero) {
        non_zero = 0;
        uint32_t remainder = 0;
        for (size_t i = 0; i < in_len; i++) {
            uint32_t val = (remainder << 8) | tmp[i];
            tmp[i] = (uint8_t)(val / base);
            remainder = val % base;
            if (tmp[i] != 0) non_zero = 1;
        }
        *ptr++ = alphabet[remainder];
    }
    
    // Count leading zeros in input (Base58 style, preserve leading nulls as leading '0' symbol?)
    // FF70 usually is just value encoding. But preserving leading zeros is good practice for binary data.
    // Let's preserve leading zeros mapped to the first char of alphabet.
    for (size_t i = 0; i < in_len && in[i] == 0; i++) {
        *ptr++ = alphabet[0];
    }

    free(tmp);
    
    // Reverse string
    size_t len = ptr - out_str;
    for (size_t i = 0; i < len / 2; i++) {
        char t = out_str[i];
        out_str[i] = out_str[len - 1 - i];
        out_str[len - 1 - i] = t;
    }
    out_str[len] = '\0';
    return len;
}

// Helper: BaseN Decode (BigInt multiplication)
// Returns size of decoded data. -1 on error.
static int base_n_decode(const char *in, size_t in_len, const char *alphabet, size_t base, uint8_t *out, size_t out_max) {
    if (in_len == 0) return 0;

    // Estimate size: log2(Base) * len / 8
    // Allocate temporary buffer (large enough)
    size_t tmp_cap = in_len + 32; // Overestimate
    uint8_t *tmp = (uint8_t *)calloc(1, tmp_cap);
    if (!tmp) return -1;

    size_t tmp_len = 0;

    for (size_t i = 0; i < in_len; i++) {
        int val = get_char_value(in[i], alphabet);
        if (val == -1) {
            free(tmp);
            return -1; // Invalid char
        }

        // tmp = tmp * base + val
        uint32_t carry = val;
        for (size_t j = 0; j < tmp_len; j++) {
            uint32_t res = (uint32_t)tmp[j] * base + carry;
            tmp[j] = res & 0xFF;
            carry = res >> 8;
        }
        while (carry) {
            if (tmp_len >= tmp_cap) {
                free(tmp);
                return -1; // Overflow
            }
            tmp[tmp_len++] = carry & 0xFF;
            carry >>= 8;
        }
    }

    // Handle leading zeros (first char of alphabet)
    size_t leading_zeros = 0;
    while (leading_zeros < in_len && in[leading_zeros] == alphabet[0]) {
        leading_zeros++;
    }

    size_t total_len = tmp_len + leading_zeros;
    if (total_len > out_max) {
        free(tmp);
        return -1; // Buffer too small
    }

    // Output is currently reversed in tmp (Little Endian)
    // Write leading zeros
    memset(out, 0, leading_zeros);
    // Write number (reversed)
    for (size_t i = 0; i < tmp_len; i++) {
        out[leading_zeros + tmp_len - 1 - i] = tmp[i];
    }

    free(tmp);
    return (int)total_len;
}

void ff70_frame_free(ff70_frame_t *frame) {
    if (frame && frame->payload) {
        free(frame->payload);
        frame->payload = NULL;
    }
}

size_t ff70_encode(const uint8_t *bin, size_t bin_len, 
                   const char *header, const char *exclude_chars, const char *meta,
                   char *out, size_t out_len) {
    char alphabet[72];
    size_t base = build_alphabet(exclude_chars, DEFAULT_SEPARATOR, alphabet);

    // 1. Calculate Checksum
    uint8_t checksum[CHECKSUM_SIZE];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, bin, bin_len);
    uint8_t full_hash[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, full_hash, BLAKE3_OUT_LEN);
    memcpy(checksum, full_hash, CHECKSUM_SIZE);

    // 2. Encode Data and Checksum
    // Alloc temp buffers
    size_t max_enc_len = bin_len * 2 + 16; // Rough estimate
    char *enc_data = (char*)malloc(max_enc_len);
    char *enc_sum = (char*)malloc(64);
    if (!enc_data || !enc_sum) { free(enc_data); free(enc_sum); return 0; }

    base_n_encode(bin, bin_len, alphabet, base, enc_data);
    base_n_encode(checksum, CHECKSUM_SIZE, alphabet, base, enc_sum);

    // 3. Format Output
    // [Header](Config){Data|Sum}[Meta]
    // Config: If exclude_chars is provided, formatted as "-chars"
    char config_str[64] = "";
    if (exclude_chars && *exclude_chars) {
        snprintf(config_str, sizeof(config_str), "-%s", exclude_chars);
    }

    int written = snprintf(out, out_len, "[%s](%s){%s%c%s}[%s]",
        header ? header : "",
        config_str,
        enc_data, DEFAULT_SEPARATOR, enc_sum,
        meta ? meta : ""
    );

    free(enc_data);
    free(enc_sum);

    if (written < 0 || (size_t)written >= out_len) return 0;
    return written;
}

int ff70_decode(const char *ff70_str, ff70_frame_t *frame) {
    if (!ff70_str || !frame) return -1;
    memset(frame, 0, sizeof(ff70_frame_t));

    // Simple parser state machine or strchr hunting
    const char *p = ff70_str;
    
    // 1. [Header]
    if (*p != '[') return -1;
    const char *end = strchr(p, ']');
    if (!end) return -1;
    size_t len = end - p - 1;
    if (len >= sizeof(frame->header)) len = sizeof(frame->header) - 1;
    strncpy(frame->header, p + 1, len);
    p = end + 1;

    // 2. (Config)
    if (*p != '(') return -1;
    end = strchr(p, ')');
    if (!end) return -1;
    len = end - p - 1;
    if (len >= sizeof(frame->config)) len = sizeof(frame->config) - 1;
    strncpy(frame->config, p + 1, len);
    p = end + 1;

    // Parse Config to build alphabet
    char alphabet[72];
    char exclude[64] = "";
    if (frame->config[0] == '-') {
        strncpy(exclude, frame->config + 1, sizeof(exclude) - 1);
    }
    size_t base = build_alphabet(exclude, DEFAULT_SEPARATOR, alphabet);

    // 3. {Payload}
    if (*p != '{') return -1;
    end = strchr(p, '}');
    if (!end) return -1;
    
    // Extract payload content (Data|Sum)
    size_t payload_content_len = end - p - 1;
    char *content = (char*)malloc(payload_content_len + 1);
    if (!content) return -3;
    strncpy(content, p + 1, payload_content_len);
    content[payload_content_len] = '\0';
    p = end + 1;

    // Split by Separator
    char *sep = strchr(content, DEFAULT_SEPARATOR);
    if (!sep) {
        free(content);
        return -1; // Missing separator
    }
    *sep = '\0';
    char *str_data = content;
    char *str_sum = sep + 1;

    // Decode Data
    size_t data_max_len = payload_content_len; // Safe upper bound
    frame->payload = (uint8_t*)malloc(data_max_len);
    if (!frame->payload) { free(content); return -3; }
    
    int dec_len = base_n_decode(str_data, strlen(str_data), alphabet, base, frame->payload, data_max_len);
    if (dec_len < 0) {
        free(content);
        ff70_frame_free(frame);
        return -1; // Decode error
    }
    frame->payload_len = dec_len;

    // Decode Checksum
    uint8_t checksum[CHECKSUM_SIZE + 4]; // little extra safety
    int sum_len = base_n_decode(str_sum, strlen(str_sum), alphabet, base, checksum, sizeof(checksum));
    if (sum_len != CHECKSUM_SIZE) {
        free(content);
        ff70_frame_free(frame);
        return -2; // Checksum size mismatch
    }

    // Verify Checksum
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, frame->payload, frame->payload_len);
    uint8_t full_hash[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, full_hash, BLAKE3_OUT_LEN);

    if (memcmp(checksum, full_hash, CHECKSUM_SIZE) != 0) {
        free(content);
        ff70_frame_free(frame);
        return -2; // Checksum mismatch
    }

    free(content);

    // 4. [Meta] (Optional)
    if (*p == '[') {
        end = strchr(p, ']');
        if (end) {
            len = end - p - 1;
            if (len >= sizeof(frame->meta)) len = sizeof(frame->meta) - 1;
            strncpy(frame->meta, p + 1, len);
        }
    }

    return 0;
}
