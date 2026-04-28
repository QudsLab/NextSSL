/* pow_parser.c — challenge/solution codec and name normalisation.
 *
 * The encode/decode implementation is a minimal JSON-over-base64 skeleton.
 * Replace with a proper JSON library (cJSON, jsmn) for production use.
 */
#include "pow_parser.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* -------------------------------------------------------------------------
 * Name normalisation
 * ------------------------------------------------------------------------- */
void pow_algo_name_normalise(char *name) {
    if (!name) return;
    for (char *p = name; *p; p++) {
        if (*p == '_') *p = '-';
    }
}

/* -------------------------------------------------------------------------
 * Minimal base64 codec (RFC 4648, no line wrapping)
 * ------------------------------------------------------------------------- */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int base64_encode(const uint8_t *src, size_t src_len,
                          char *dst, size_t dst_cap) {
    size_t out_len = 4 * ((src_len + 2) / 3);
    if (out_len + 1 > dst_cap) return -1;
    size_t i = 0, j = 0;
    while (i < src_len) {
        uint32_t octet_a = i < src_len ? src[i++] : 0;
        uint32_t octet_b = i < src_len ? src[i++] : 0;
        uint32_t octet_c = i < src_len ? src[i++] : 0;
        uint32_t triple  = (octet_a << 16) | (octet_b << 8) | octet_c;
        dst[j++] = b64_table[(triple >> 18) & 0x3F];
        dst[j++] = b64_table[(triple >> 12) & 0x3F];
        dst[j++] = b64_table[(triple >>  6) & 0x3F];
        dst[j++] = b64_table[(triple      ) & 0x3F];
    }
    /* padding */
    size_t pad = src_len % 3;
    if (pad == 1) { dst[j-2] = '='; dst[j-1] = '='; }
    else if (pad == 2) { dst[j-1] = '='; }
    dst[j] = '\0';
    return 0;
}

static int base64_decode(const char *src, uint8_t *dst,
                          size_t dst_cap, size_t *out_len) {
    size_t src_len = strlen(src);
    if (src_len % 4 != 0) return -1;
    size_t dec_len = src_len / 4 * 3;
    if (src_len >= 1 && src[src_len-1] == '=') dec_len--;
    if (src_len >= 2 && src[src_len-2] == '=') dec_len--;
    if (dec_len > dst_cap) return -1;
    size_t i = 0, j = 0;
    while (i < src_len) {
        int a = b64_decode_char(src[i++]);
        int b = b64_decode_char(src[i++]);
        int c = (src[i] == '=') ? 0 : b64_decode_char(src[i]); i++;
        int d = (src[i] == '=') ? 0 : b64_decode_char(src[i]); i++;
        if (a < 0 || b < 0) return -1;
        uint32_t triple = ((uint32_t)a << 18)|((uint32_t)b << 12)|
                          ((uint32_t)c <<  6)|((uint32_t)d      );
        if (j < dec_len) dst[j++] = (triple >> 16) & 0xFF;
        if (j < dec_len) dst[j++] = (triple >>  8) & 0xFF;
        if (j < dec_len) dst[j++] = (triple      ) & 0xFF;
    }
    if (out_len) *out_len = dec_len;
    return 0;
}

/* -------------------------------------------------------------------------
 * Minimal JSON field readers
 * ------------------------------------------------------------------------- */
static int json_str(const char *json, const char *key,
                    char *out, size_t out_cap) {
    char kbuf[96];
    snprintf(kbuf, sizeof(kbuf), "\"%s\":\"", key);
    const char *p = strstr(json, kbuf);
    if (!p) return -1;
    p += strlen(kbuf);
    const char *e = strchr(p, '"');
    if (!e) return -1;
    size_t n = (size_t)(e - p);
    if (n >= out_cap) return -1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

static int json_u64(const char *json, const char *key, uint64_t *out) {
    char kbuf[96];
    snprintf(kbuf, sizeof(kbuf), "\"%s\":", key);
    const char *p = strstr(json, kbuf);
    if (!p) return -1;
    p += strlen(kbuf);
    *out = strtoull(p, NULL, 10);
    return 0;
}

/* -------------------------------------------------------------------------
 * Challenge encode / decode
 * ------------------------------------------------------------------------- */
int pow_challenge_decode(const char *b64, pow_challenge_t *out) {
    if (!b64 || !out) return -1;

    uint8_t buf[4096];
    size_t  dec_len = 0;
    if (base64_decode(b64, buf, sizeof(buf) - 1, &dec_len) != 0) return -1;
    buf[dec_len] = '\0';
    const char *json = (const char *)buf;

    uint64_t v = 0;
    if (json_u64(json, "version", &v) == 0) out->version = (uint8_t)v;

    json_str(json, "algorithm_id", out->algorithm_id, sizeof(out->algorithm_id));
    /* normalise name: "sha3_256" → "sha3-256" */
    pow_algo_name_normalise(out->algorithm_id);

    if (json_u64(json, "difficulty_bits", &v) == 0)
        out->difficulty_bits = (uint32_t)v;
    json_u64(json, "wu",           &out->wu);
    json_u64(json, "mu",           &out->mu);
    json_u64(json, "expires_unix", &out->expires_unix);

    return 0;
}

int pow_challenge_encode(const pow_challenge_t *c, char *out_buf, size_t out_len) {
    if (!c || !out_buf || out_len == 0) return -1;
    char json[2048];
    int n = snprintf(json, sizeof(json),
        "{\"version\":%u,\"algorithm_id\":\"%s\","
        "\"difficulty_bits\":%u,\"wu\":%llu,\"mu\":%llu,"
        "\"expires_unix\":%llu}",
        c->version, c->algorithm_id,
        c->difficulty_bits,
        (unsigned long long)c->wu,
        (unsigned long long)c->mu,
        (unsigned long long)c->expires_unix);
    if (n < 0 || (size_t)n >= sizeof(json)) return -1;
    return base64_encode((uint8_t *)json, (size_t)n, out_buf, out_len);
}

int pow_solution_decode(const char *b64, pow_solution_t *out) {
    if (!b64 || !out) return -1;
    uint8_t buf[2048];
    size_t  dec_len = 0;
    if (base64_decode(b64, buf, sizeof(buf) - 1, &dec_len) != 0) return -1;
    buf[dec_len] = '\0';
    const char *json = (const char *)buf;
    uint64_t v = 0;
    json_u64(json, "nonce", &out->nonce);
    if (json_u64(json, "hash_output_len", &v) == 0) out->hash_output_len = (size_t)v;
    json_u64(json, "attempts", &out->attempts);
    return 0;
}

int pow_solution_encode(const pow_solution_t *s, char *out_buf, size_t out_len) {
    if (!s || !out_buf || out_len == 0) return -1;
    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"nonce\":%llu,\"hash_output_len\":%zu,\"attempts\":%llu}",
        (unsigned long long)s->nonce,
        s->hash_output_len,
        (unsigned long long)s->attempts);
    if (n < 0 || (size_t)n >= sizeof(json)) return -1;
    return base64_encode((uint8_t *)json, (size_t)n, out_buf, out_len);
}
