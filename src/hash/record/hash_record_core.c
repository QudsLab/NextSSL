#include "hash_record_core.h"

#include "../../encoding/base16.h"
#include "../adapters/kdf_adapters.h"
#include "../../seed/hash/hash_registry.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define NEXTSSL_RECORD_PREFIX "$nss$1$algo="
#define NEXTSSL_RECORD_PARAMS "$params="
#define NEXTSSL_RECORD_SALT "$salt="
#define NEXTSSL_RECORD_OUT "$out="

static int is_kdf_algo(const char *algo)
{
    return strcmp(algo, "argon2d") == 0 ||
           strcmp(algo, "argon2i") == 0 ||
           strcmp(algo, "argon2id") == 0 ||
           strcmp(algo, "bcrypt") == 0 ||
           strcmp(algo, "catena") == 0 ||
           strcmp(algo, "lyra2") == 0 ||
           strcmp(algo, "scrypt") == 0 ||
           strcmp(algo, "yescrypt") == 0 ||
           strcmp(algo, "balloon") == 0 ||
           strcmp(algo, "pomelo") == 0 ||
           strcmp(algo, "makwa") == 0;
}

static size_t default_salt_len(const char *algo)
{
    if (strcmp(algo, "balloon") == 0 ||
        strcmp(algo, "pomelo") == 0 ||
        strcmp(algo, "makwa") == 0) {
        return 32;
    }
    return 16;
}

static int is_fixed_salt_algo(const char *algo)
{
    return strcmp(algo, "bcrypt") == 0 ||
           strcmp(algo, "balloon") == 0 ||
           strcmp(algo, "pomelo") == 0 ||
           strcmp(algo, "makwa") == 0;
}

static size_t default_kdf_out_len(const char *algo)
{
    if (strcmp(algo, "bcrypt") == 0 || strcmp(algo, "balloon") == 0) {
        return 32;
    }
    return 32;
}

static void apply_kdf_defaults(const char *algo,
                               nextssl_hash_config_t *cfg,
                               size_t *compute_len)
{
    if (strcmp(algo, "argon2d") == 0 ||
        strcmp(algo, "argon2i") == 0 ||
        strcmp(algo, "argon2id") == 0) {
        if (cfg->memory == 0) cfg->memory = 65536;
        if (cfg->iterations == 0) cfg->iterations = 2;
        if (cfg->parallelism == 0) cfg->parallelism = 1;
        if (cfg->key_length == 0) cfg->key_length = 32;
        *compute_len = cfg->key_length;
        return;
    }

    if (strcmp(algo, "scrypt") == 0 || strcmp(algo, "yescrypt") == 0) {
        if (cfg->N == 0) cfg->N = 16384;
        if (cfg->r == 0) cfg->r = 8;
        if (cfg->p == 0) cfg->p = 1;
        if (cfg->key_length == 0) cfg->key_length = 32;
        *compute_len = cfg->key_length;
        return;
    }

    if (strcmp(algo, "bcrypt") == 0) {
        if (cfg->work_factor == 0) cfg->work_factor = 10;
        *compute_len = 32;
        return;
    }

    if (strcmp(algo, "catena") == 0) {
        if (cfg->lambda == 0) cfg->lambda = 2;
        if (cfg->garlic == 0) cfg->garlic = 14;
        if (cfg->key_length == 0) cfg->key_length = 32;
        *compute_len = cfg->key_length;
        return;
    }

    if (strcmp(algo, "lyra2") == 0) {
        if (cfg->t_cost == 0) cfg->t_cost = 1;
        if (cfg->nrows == 0) cfg->nrows = 8;
        if (cfg->ncols == 0) cfg->ncols = 256;
        if (cfg->key_length == 0) cfg->key_length = 32;
        *compute_len = cfg->key_length;
        return;
    }

    if (strcmp(algo, "balloon") == 0) {
        if (cfg->s_cost == 0) cfg->s_cost = 1024;
        if (cfg->iterations == 0) cfg->iterations = 3;
        if (cfg->n_threads == 0) cfg->n_threads = 1;
        *compute_len = 32;
        return;
    }

    if (strcmp(algo, "pomelo") == 0) {
        if (cfg->t_cost_u == 0) cfg->t_cost_u = 1;
        if (cfg->m_cost_u == 0) cfg->m_cost_u = 14;
        if (cfg->key_length == 0) cfg->key_length = 32;
        *compute_len = cfg->key_length;
        return;
    }

    if (strcmp(algo, "makwa") == 0) {
        if (cfg->work_factor == 0) cfg->work_factor = 4096;
        if (cfg->key_length == 0) cfg->key_length = 32;
        *compute_len = cfg->key_length;
        return;
    }

    *compute_len = default_kdf_out_len(algo);
}

static int build_params_string(const char *algo,
                               const nextssl_hash_config_t *cfg,
                               size_t compute_len,
                               char *params,
                               size_t params_cap)
{
    int wrote;

    if (!algo || !cfg || !params || params_cap == 0) return -1;

    if (!is_kdf_algo(algo)) {
        params[0] = '\0';
        return 0;
    }

    if (strcmp(algo, "argon2d") == 0 || strcmp(algo, "argon2i") == 0 || strcmp(algo, "argon2id") == 0) {
        wrote = snprintf(params, params_cap, "m=%u,t=%u,p=%u,dk=%zu",
                         cfg->memory, cfg->iterations, cfg->parallelism, compute_len);
    } else if (strcmp(algo, "scrypt") == 0 || strcmp(algo, "yescrypt") == 0) {
        wrote = snprintf(params, params_cap, "N=%llu,r=%u,p=%u,dk=%zu",
                         (unsigned long long)cfg->N, cfg->r, cfg->p, compute_len);
    } else if (strcmp(algo, "bcrypt") == 0) {
        wrote = snprintf(params, params_cap, "wf=%u,dk=%zu",
                         cfg->work_factor, compute_len);
    } else if (strcmp(algo, "catena") == 0) {
        wrote = snprintf(params, params_cap, "lambda=%u,garlic=%u,dk=%zu",
                         cfg->lambda, cfg->garlic, compute_len);
    } else if (strcmp(algo, "lyra2") == 0) {
        wrote = snprintf(params, params_cap, "t=%llu,rows=%u,cols=%u,dk=%zu",
                         (unsigned long long)cfg->t_cost, cfg->nrows, cfg->ncols, compute_len);
    } else if (strcmp(algo, "balloon") == 0) {
        wrote = snprintf(params, params_cap, "s=%u,t=%u,threads=%u,dk=%zu",
                         cfg->s_cost, cfg->iterations, cfg->n_threads, compute_len);
    } else if (strcmp(algo, "pomelo") == 0) {
        wrote = snprintf(params, params_cap, "t=%u,m=%u,dk=%zu",
                         cfg->t_cost_u, cfg->m_cost_u, compute_len);
    } else if (strcmp(algo, "makwa") == 0) {
        wrote = snprintf(params, params_cap, "wf=%u,dk=%zu",
                         cfg->work_factor, compute_len);
    } else {
        return -1;
    }

    return (wrote < 0 || (size_t)wrote >= params_cap) ? -1 : 0;
}

static int hex_encode_alloc(const uint8_t *input, size_t input_len, char **out_hex)
{
    char *buf;
    if (!out_hex) return -1;
    *out_hex = NULL;
    buf = (char *)malloc((input_len * 2) + 1);
    if (!buf) return -1;
    if (radix_base16_encode(input, input_len, buf, (input_len * 2) + 1) != 0) {
        free(buf);
        return -1;
    }
    *out_hex = buf;
    return 0;
}

static int hex_decode_alloc(const char *hex, uint8_t **out, size_t *out_len)
{
    size_t hex_len;
    uint8_t *buf;
    size_t decoded_len = 0;

    if (!hex || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    hex_len = strlen(hex);
    if (hex_len == 0) {
        buf = (uint8_t *)malloc(1);
        if (!buf) return -1;
        *out = buf;
        *out_len = 0;
        return 0;
    }

    buf = (uint8_t *)malloc((hex_len / 2) + 1);
    if (!buf) return -1;
    if (radix_base16_decode(hex, hex_len, buf, (hex_len / 2) + 1, &decoded_len) != 0) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = decoded_len;
    return 0;
}

static int consttime_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; ++i) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static int parse_record_fields(const char *record,
                               char **algo,
                               char **params,
                               char **salt_hex,
                               char **out_hex)
{
    const char *p;
    const char *params_tag;
    const char *salt_tag;
    const char *out_tag;
    size_t algo_len;
    size_t params_len;
    size_t salt_len;
    size_t out_len;

    if (!record || !algo || !params || !salt_hex || !out_hex) return -1;
    *algo = *params = *salt_hex = *out_hex = NULL;

    if (strncmp(record, NEXTSSL_RECORD_PREFIX, strlen(NEXTSSL_RECORD_PREFIX)) != 0) return -1;
    p = record + strlen(NEXTSSL_RECORD_PREFIX);
    params_tag = strstr(p, NEXTSSL_RECORD_PARAMS);
    if (!params_tag) return -1;
    salt_tag = strstr(params_tag + strlen(NEXTSSL_RECORD_PARAMS), NEXTSSL_RECORD_SALT);
    if (!salt_tag) return -1;
    out_tag = strstr(salt_tag + strlen(NEXTSSL_RECORD_SALT), NEXTSSL_RECORD_OUT);
    if (!out_tag) return -1;

    algo_len = (size_t)(params_tag - p);
    params_len = (size_t)(salt_tag - (params_tag + strlen(NEXTSSL_RECORD_PARAMS)));
    salt_len = (size_t)(out_tag - (salt_tag + strlen(NEXTSSL_RECORD_SALT)));
    out_len = strlen(out_tag + strlen(NEXTSSL_RECORD_OUT));

    *algo = (char *)malloc(algo_len + 1);
    *params = (char *)malloc(params_len + 1);
    *salt_hex = (char *)malloc(salt_len + 1);
    *out_hex = (char *)malloc(out_len + 1);
    if (!*algo || !*params || !*salt_hex || !*out_hex) {
        free(*algo); free(*params); free(*salt_hex); free(*out_hex);
        *algo = *params = *salt_hex = *out_hex = NULL;
        return -1;
    }

    memcpy(*algo, p, algo_len); (*algo)[algo_len] = '\0';
    memcpy(*params, params_tag + strlen(NEXTSSL_RECORD_PARAMS), params_len); (*params)[params_len] = '\0';
    memcpy(*salt_hex, salt_tag + strlen(NEXTSSL_RECORD_SALT), salt_len); (*salt_hex)[salt_len] = '\0';
    memcpy(*out_hex, out_tag + strlen(NEXTSSL_RECORD_OUT), out_len); (*out_hex)[out_len] = '\0';
    return 0;
}

static int parse_u64(const char *s, uint64_t *out)
{
    char *end = NULL;
    unsigned long long val;
    if (!s || !out || *s == '\0') return -1;
    val = strtoull(s, &end, 10);
    if (!end || *end != '\0') return -1;
    *out = (uint64_t)val;
    return 0;
}

static int parse_params_into_config(const char *algo,
                                    const char *params,
                                    size_t out_len,
                                    nextssl_hash_config_t *cfg)
{
    char *copy;
    char *cursor;

    if (!algo || !params || !cfg) return -1;
    memset(cfg, 0, sizeof(*cfg));

    if (!is_kdf_algo(algo)) return params[0] == '\0' ? 0 : -1;

    copy = (char *)malloc(strlen(params) + 1);
    if (!copy) return -1;
    memcpy(copy, params, strlen(params) + 1);

    cursor = copy;
    while (*cursor) {
        char *token = cursor;
        char *eq = strchr(token, '=');
        char *comma;
        const char *key;
        const char *val;
        uint64_t parsed = 0;

        comma = strchr(token, ',');
        if (comma) {
            *comma = '\0';
            cursor = comma + 1;
        } else {
            cursor += strlen(cursor);
        }

        if (!eq) { free(copy); return -1; }
        *eq = '\0';
        key = token;
        val = eq + 1;
        if (parse_u64(val, &parsed) != 0) { free(copy); return -1; }

        if (strcmp(key, "m") == 0) {
            if (strcmp(algo, "pomelo") == 0) cfg->m_cost_u = (unsigned int)parsed;
            else cfg->memory = (uint32_t)parsed;
        }
        else if (strcmp(key, "t") == 0) {
            if (strcmp(algo, "lyra2") == 0) cfg->t_cost = parsed;
            else if (strcmp(algo, "pomelo") == 0) cfg->t_cost_u = (unsigned int)parsed;
            else cfg->iterations = (uint32_t)parsed;
        }
        else if (strcmp(key, "p") == 0) {
            if (strcmp(algo, "argon2d") == 0 || strcmp(algo, "argon2i") == 0 || strcmp(algo, "argon2id") == 0) cfg->parallelism = (uint32_t)parsed;
            else cfg->p = (uint32_t)parsed;
        }
        else if (strcmp(key, "dk") == 0) cfg->key_length = (uint32_t)parsed;
        else if (strcmp(key, "N") == 0) cfg->N = parsed;
        else if (strcmp(key, "r") == 0) cfg->r = (uint32_t)parsed;
        else if (strcmp(key, "wf") == 0) cfg->work_factor = (uint32_t)parsed;
        else if (strcmp(key, "lambda") == 0) cfg->lambda = (uint8_t)parsed;
        else if (strcmp(key, "garlic") == 0) cfg->garlic = (uint8_t)parsed;
        else if (strcmp(key, "rows") == 0) cfg->nrows = (uint32_t)parsed;
        else if (strcmp(key, "cols") == 0) cfg->ncols = (uint32_t)parsed;
        else if (strcmp(key, "s") == 0) cfg->s_cost = (uint32_t)parsed;
        else if (strcmp(key, "threads") == 0) cfg->n_threads = (uint32_t)parsed;
        else { free(copy); return -1; }
    }

    free(copy);
    apply_kdf_defaults(algo, cfg, &out_len);
    return 0;
}

static int build_record(const char *algo,
                        const char *params,
                        const char *salt_hex,
                        const char *out_hex,
                        char *record_out,
                        size_t record_cap,
                        size_t *record_len)
{
    int wrote;
    if (!algo || !params || !salt_hex || !out_hex || !record_out || !record_len) return -1;
    wrote = snprintf(record_out, record_cap, "$nss$1$algo=%s$params=%s$salt=%s$out=%s",
                     algo, params, salt_hex, out_hex);
    if (wrote < 0 || (size_t)wrote >= record_cap) return -1;
    *record_len = (size_t)wrote;
    return 0;
}

int nextssl_record_format_plain_internal(
    const char    *algo,
    const uint8_t *data,
    size_t         data_len,
    char          *record_out,
    size_t         record_cap,
    size_t        *record_len)
{
    const hash_ops_t *ops;
    uint8_t *out = NULL;
    char *out_hex = NULL;
    int rc = -1;

    if (!algo || !record_out || !record_len) return -1;
    ops = hash_lookup_by_name(algo);
    if (!ops || is_kdf_algo(algo)) return -1;

    out = (uint8_t *)malloc(ops->digest_size ? ops->digest_size : 1);
    if (!out) return -1;
    if (nextssl_hash(algo, data, data_len, out, ops->digest_size, NULL) != 0) goto cleanup;
    if (hex_encode_alloc(out, ops->digest_size, &out_hex) != 0) goto cleanup;
    rc = build_record(algo, "", "", out_hex, record_out, record_cap, record_len);

cleanup:
    free(out_hex);
    free(out);
    return rc;
}

int nextssl_record_verify_plain_internal(
    const char    *algo,
    const uint8_t *data,
    size_t         data_len,
    const char    *record,
    int           *out_match)
{
    char *parsed_algo = NULL;
    char *params = NULL;
    char *salt_hex = NULL;
    char *out_hex = NULL;
    uint8_t *expected = NULL;
    uint8_t *actual = NULL;
    size_t expected_len = 0;
    int rc = -1;

    if (!algo || !record || !out_match) return -1;
    *out_match = 0;
    if (parse_record_fields(record, &parsed_algo, &params, &salt_hex, &out_hex) != 0) goto cleanup;
    if (strcmp(parsed_algo, algo) != 0) goto cleanup;
    if (params[0] != '\0' || salt_hex[0] != '\0') goto cleanup;
    if (hex_decode_alloc(out_hex, &expected, &expected_len) != 0) goto cleanup;
    actual = (uint8_t *)malloc(expected_len ? expected_len : 1);
    if (!actual) goto cleanup;
    if (nextssl_hash(algo, data, data_len, actual, expected_len, NULL) != 0) goto cleanup;
    *out_match = consttime_eq(expected, actual, expected_len);
    rc = 0;

cleanup:
    free(parsed_algo); free(params); free(salt_hex); free(out_hex);
    free(expected); free(actual);
    return rc;
}

int nextssl_record_format_kdf_internal(
    const char                  *algo,
    const uint8_t               *data,
    size_t                       data_len,
    const nextssl_hash_config_t *config,
    char                        *record_out,
    size_t                       record_cap,
    size_t                      *record_len)
{
    nextssl_hash_config_t cfg;
    uint8_t auto_salt[32];
    size_t compute_len = 0;
    uint8_t *out = NULL;
    char *out_hex = NULL;
    char *salt_hex = NULL;
    char params[128];
    int rc = -1;

    if (!algo || !record_out || !record_len || !is_kdf_algo(algo)) return -1;
    memset(&cfg, 0, sizeof(cfg));
    if (config) cfg = *config;
    apply_kdf_defaults(algo, &cfg, &compute_len);

    if (!cfg.salt) {
        size_t salt_len = default_salt_len(algo);
        if (salt_len > sizeof(auto_salt)) return -1;
        if (kdf_adapter_fill_auto_salt(auto_salt, salt_len) != 0) return -1;
        cfg.salt = auto_salt;
        cfg.salt_len = salt_len;
    } else {
        if (cfg.salt_len == 0) return -1;
        if (is_fixed_salt_algo(algo) && cfg.salt_len < default_salt_len(algo)) return -1;
    }

    out = (uint8_t *)malloc(compute_len ? compute_len : 1);
    if (!out) return -1;
    if (nextssl_hash(algo, data, data_len, out, compute_len, &cfg) != 0) goto cleanup;
    if (build_params_string(algo, &cfg, compute_len, params, sizeof(params)) != 0) goto cleanup;
    if (hex_encode_alloc(cfg.salt, cfg.salt_len, &salt_hex) != 0) goto cleanup;
    if (hex_encode_alloc(out, compute_len, &out_hex) != 0) goto cleanup;
    rc = build_record(algo, params, salt_hex, out_hex, record_out, record_cap, record_len);

cleanup:
    free(out_hex);
    free(salt_hex);
    free(out);
    return rc;
}

int nextssl_record_verify_kdf_internal(
    const char    *algo,
    const uint8_t *data,
    size_t         data_len,
    const char    *record,
    int           *out_match)
{
    char *parsed_algo = NULL;
    char *params = NULL;
    char *salt_hex = NULL;
    char *out_hex = NULL;
    uint8_t *salt = NULL;
    uint8_t *expected = NULL;
    uint8_t *actual = NULL;
    size_t salt_len = 0;
    size_t expected_len = 0;
    nextssl_hash_config_t cfg;
    int rc = -1;

    if (!algo || !record || !out_match || !is_kdf_algo(algo)) return -1;
    *out_match = 0;
    memset(&cfg, 0, sizeof(cfg));

    if (parse_record_fields(record, &parsed_algo, &params, &salt_hex, &out_hex) != 0) goto cleanup;
    if (strcmp(parsed_algo, algo) != 0) goto cleanup;
    if (hex_decode_alloc(salt_hex, &salt, &salt_len) != 0) goto cleanup;
    if (hex_decode_alloc(out_hex, &expected, &expected_len) != 0) goto cleanup;
    if (parse_params_into_config(algo, params, expected_len, &cfg) != 0) goto cleanup;
    cfg.salt = salt;
    cfg.salt_len = salt_len;
    actual = (uint8_t *)malloc(expected_len ? expected_len : 1);
    if (!actual) goto cleanup;
    if (nextssl_hash(algo, data, data_len, actual, expected_len, &cfg) != 0) goto cleanup;
    *out_match = consttime_eq(expected, actual, expected_len);
    rc = 0;

cleanup:
    free(parsed_algo); free(params); free(salt_hex); free(out_hex);
    free(salt); free(expected); free(actual);
    return rc;
}
