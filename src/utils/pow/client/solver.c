#include "pow_client.h"
#include "core/pow_primitive_fast.h"
#include "core/pow_primitive_memory_hard.h"
#include "core/pow_primitive_sponge_xof.h"
#include "core/pow_legacy_alive.h"
#include "core/pow_legacy_unsafe.h"
#include "../../../primitives/hash/memory_hard/utils/argon2.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

// Helper: Map linear index to char from ranges
static uint8_t get_char_from_ranges(uint32_t index, const PoWCharRange *ranges, uint32_t num_ranges) {
    for (uint32_t i = 0; i < num_ranges; i++) {
        uint32_t range_len = ranges[i].max_char - ranges[i].min_char + 1;
        if (index < range_len) {
            return ranges[i].min_char + index;
        }
        index -= range_len;
    }
    return 0; // Should not happen if index is within total size
}

static uint32_t get_total_chars(const PoWCharRange *ranges, uint32_t num_ranges) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < num_ranges; i++) {
        count += (ranges[i].max_char - ranges[i].min_char + 1);
    }
    return count;
}

static void pow_clear_msg(char *buf, size_t len) {
    if (buf && len > 0) buf[0] = '\0';
}

static void pow_append_item(char *buf, size_t len, const char *name) {
    if (!buf || len == 0 || !name || name[0] == '\0') return;
    size_t used = strlen(buf);
    if (used >= len - 1) return;
    if (used == 0) {
        snprintf(buf, len, "%s", name);
    } else {
        snprintf(buf + used, len - used, ", %s", name);
    }
}

static void pow_set_error(char *buf, size_t len, const char *prefix, const char *items) {
    if (!buf || len == 0) return;
    if (items && items[0] != '\0') {
        snprintf(buf, len, "%s%s", prefix, items);
    } else {
        buf[0] = '\0';
    }
}

static size_t pow_default_out_len(PoWAlgorithm algo) {
    switch (algo) {
        case POW_ALGO_BLAKE3: return 32;
        case POW_ALGO_SHA256: return 32;
        case POW_ALGO_SHA3_256: return 32;
        case POW_ALGO_ARGON2ID: return 32;
        case POW_ALGO_MD5: return 16;
        case POW_ALGO_SHA1: return 20;
        default: return 32;
    }
}

PoWError pow_client_hash(PoWAlgorithm algo, const PoWHashArgs *args, char *error_msg, size_t error_len, char *warning_msg, size_t warning_len) {
    pow_clear_msg(error_msg, error_len);
    pow_clear_msg(warning_msg, warning_len);

    if (!args) {
        pow_set_error(error_msg, error_len, "missing: ", "args");
        return POW_ERR_INVALID_FORMAT;
    }

    char missing[256];
    char unused[256];
    pow_clear_msg(missing, sizeof(missing));
    pow_clear_msg(unused, sizeof(unused));

    const uint8_t *msg = args->msg;
    size_t msg_len = args->msg_len;
    const uint8_t *nonce = args->nonce;
    size_t nonce_len = args->nonce_len;
    uint8_t *out_hash = args->out_hash;
    size_t out_len = args->out_len;

    if (out_len == 0) out_len = pow_default_out_len(algo);

    switch (algo) {
        case POW_ALGO_BLAKE3:
        case POW_ALGO_SHA256:
        case POW_ALGO_SHA3_256:
        case POW_ALGO_MD5:
        case POW_ALGO_SHA1: {
            if (!msg || msg_len == 0) pow_append_item(missing, sizeof(missing), "msg");
            if (!out_hash || out_len == 0) pow_append_item(missing, sizeof(missing), "out_hash");
            if (args->pwd || args->pwd_len > 0) pow_append_item(unused, sizeof(unused), "pwd");
            if (args->salt || args->salt_len > 0) pow_append_item(unused, sizeof(unused), "salt");
            if (args->secret || args->secret_len > 0) pow_append_item(unused, sizeof(unused), "secret");
            if (args->ad || args->ad_len > 0) pow_append_item(unused, sizeof(unused), "ad");
            if (args->t_cost > 0) pow_append_item(unused, sizeof(unused), "t_cost");
            if (args->m_cost_kb > 0) pow_append_item(unused, sizeof(unused), "m_cost_kb");
            if (args->parallelism > 0) pow_append_item(unused, sizeof(unused), "parallelism");
            if (args->encoded) pow_append_item(unused, sizeof(unused), "encoded");
            if (args->encoded_len > 0) pow_append_item(unused, sizeof(unused), "encoded_len");

            if (missing[0] != '\0') {
                pow_set_error(error_msg, error_len, "missing: ", missing);
                return POW_ERR_INVALID_FORMAT;
            }

            if (unused[0] != '\0') pow_set_error(warning_msg, warning_len, "unused: ", unused);

            int ret = 0;
            if (algo == POW_ALGO_BLAKE3) ret = pow_hash_blake3(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
            else if (algo == POW_ALGO_SHA256) ret = pow_hash_sha256(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
            else if (algo == POW_ALGO_SHA3_256) ret = pow_hash_sha3_256(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
            else if (algo == POW_ALGO_MD5) ret = pow_hash_md5(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
            else if (algo == POW_ALGO_SHA1) ret = pow_hash_sha1(msg, msg_len, nonce, nonce_len, out_hash, out_len, NULL);
            else return POW_ERR_UNKNOWN_ALGO;
            return ret == 0 ? POW_OK : POW_ERR_INTERNAL;
        }
        case POW_ALGO_ARGON2ID: {
            const uint8_t *pwd = args->pwd ? args->pwd : msg;
            size_t pwd_len = args->pwd ? args->pwd_len : msg_len;
            const uint8_t *salt = args->salt ? args->salt : nonce;
            size_t salt_len = args->salt ? args->salt_len : nonce_len;

            if (!pwd || pwd_len == 0) pow_append_item(missing, sizeof(missing), "pwd");
            if (!salt || salt_len == 0) pow_append_item(missing, sizeof(missing), "salt");
            if (args->t_cost == 0) pow_append_item(missing, sizeof(missing), "t_cost");
            if (args->m_cost_kb == 0) pow_append_item(missing, sizeof(missing), "m_cost_kb");
            if (args->parallelism == 0) pow_append_item(missing, sizeof(missing), "parallelism");
            if (out_len == 0) pow_append_item(missing, sizeof(missing), "hash_len");
            if (args->encoded && args->encoded_len == 0) pow_append_item(missing, sizeof(missing), "encoded_len");
            if (args->encoded_len > 0 && !args->encoded) pow_append_item(missing, sizeof(missing), "encoded");

            if (salt && salt_len > 0 && salt_len < ARGON2_MIN_SALT_LENGTH) {
                pow_set_error(error_msg, error_len, "invalid: ", "salt_len");
                return POW_ERR_INVALID_FORMAT;
            }

            if (args->pwd && msg) pow_append_item(unused, sizeof(unused), "msg");
            if (args->salt && nonce) pow_append_item(unused, sizeof(unused), "nonce");
            if (args->secret || args->secret_len > 0) pow_append_item(unused, sizeof(unused), "secret");
            if (args->ad || args->ad_len > 0) pow_append_item(unused, sizeof(unused), "ad");

            if (missing[0] != '\0') {
                pow_set_error(error_msg, error_len, "missing: ", missing);
                return POW_ERR_INVALID_FORMAT;
            }

            if (unused[0] != '\0') pow_set_error(warning_msg, warning_len, "unused: ", unused);

            Argon2Ctx ctx;
            memset(&ctx, 0, sizeof(ctx));
            if (args->pwd) {
                ctx.pwd = args->pwd;
                ctx.pwd_len = args->pwd_len;
            }
            if (args->salt) {
                ctx.salt = args->salt;
                ctx.salt_len = args->salt_len;
            }
            ctx.t_cost = args->t_cost;
            ctx.m_cost_kb = args->m_cost_kb;
            ctx.parallelism = args->parallelism;
            ctx.encoded = args->encoded;
            ctx.encoded_len = args->encoded_len;

            int ret = pow_hash_argon2id(msg, msg_len, nonce, nonce_len, out_hash, out_len, &ctx);
            return ret == 0 ? POW_OK : POW_ERR_INTERNAL;
        }
        default:
            pow_set_error(error_msg, error_len, "missing: ", "algo");
            return POW_ERR_UNKNOWN_ALGO;
    }
}

PoWError pow_client_solve(const PoWChallenge *c, PoWResult *res) {
    // 1. Safety Check
    PoWError err = pow_client_check_safety(c);
    if (err != POW_OK) return err;

    // 2. Setup
    memset(res, 0, sizeof(PoWResult));
    size_t hash_out_len = c->hash_out_len > 0 ? c->hash_out_len : pow_default_out_len(c->algo);
    if (hash_out_len > 64) return POW_ERR_INVALID_FORMAT;

    // Determine Charset
    // If no ranges, default to 0-9
    PoWCharRange default_range = { '0', '9' };
    const PoWCharRange *ranges = c->ranges;
    uint32_t num_ranges = c->num_ranges;
    if (num_ranges == 0) {
        ranges = &default_range;
        num_ranges = 1;
    }
    uint32_t charset_size = get_total_chars(ranges, num_ranges);
    if (charset_size == 0) return POW_ERR_INVALID_FORMAT;

    // 3. Solve for each input (Sequential)
    clock_t start_time = clock();
    uint32_t max_time_ticks = (c->max_time_ms > 0) ? (c->max_time_ms * CLOCKS_PER_SEC / 1000) : 
                              (CLIENT_MAX_TIME_MS * CLOCKS_PER_SEC / 1000);

    for (uint32_t i = 0; i < c->num_inputs; i++) {
        uint64_t tries = 0;
        uint8_t nonce[POW_MAX_NONCE_LEN];
        size_t nonce_len = 1;
        memset(nonce, ranges[0].min_char, sizeof(nonce)); // Init with first char
        
        // Init counter state (array of indices into charset)
        uint8_t indices[POW_MAX_NONCE_LEN] = {0};
        
        int solved = 0;
        while (!solved) {
            // Check Limits
            if (c->max_tries > 0 && tries >= c->max_tries) break;
            if ((clock() - start_time) > max_time_ticks) return POW_ERR_TIMEOUT;

            // Generate Nonce String from indices
            for (size_t k = 0; k < nonce_len; k++) {
                nonce[k] = get_char_from_ranges(indices[k], ranges, num_ranges);
            }

            // Hash
            uint8_t hash[64];
            PoWHashArgs hargs;
            memset(&hargs, 0, sizeof(hargs));
            hargs.msg = c->inputs[i];
            hargs.msg_len = c->input_lens[i];
            hargs.nonce = nonce;
            hargs.nonce_len = nonce_len;
            hargs.out_hash = hash;
            hargs.out_len = hash_out_len;
            hargs.t_cost = c->argon2_t_cost;
            hargs.m_cost_kb = c->argon2_m_cost_kb > 0 ? c->argon2_m_cost_kb : c->max_memory_kb;
            hargs.parallelism = c->argon2_parallelism;
            hargs.encoded_len = c->argon2_encoded_len;

            PoWError hash_err = pow_client_hash(c->algo, &hargs, NULL, 0, NULL, 0);
            if (hash_err != POW_OK) return hash_err;

            // Check Targets
            for (uint32_t t = 0; t < c->num_targets; t++) {
                // Check Prefix
                if (c->targets[t].prefix_len > 0) {
                    // Check repetition count
                    // E.g. Diff=2, Prefix=00. Hash must start with 00 00.
                    // If Diff=0, assume 1.
                    uint32_t diff = c->targets[t].difficulty > 0 ? c->targets[t].difficulty : 1;
                    size_t required_len = c->targets[t].prefix_len * diff;
                    if (required_len <= hash_out_len) {
                        int match = 1;
                        for (size_t r = 0; r < diff; r++) {
                            if (memcmp(hash + (r * c->targets[t].prefix_len), c->targets[t].prefix, c->targets[t].prefix_len) != 0) {
                                match = 0;
                                break;
                            }
                        }
                        if (match) {
                            solved = 1;
                            break;
                        }
                    }
                }
            }

            if (solved) {
                memcpy(res->nonces[i], nonce, nonce_len);
                res->nonce_lens[i] = nonce_len;
                break;
            }

            // Increment Nonce (BaseN counter)
            tries++;
            size_t pos = nonce_len - 1;
            while (1) {
                indices[pos]++;
                if (indices[pos] < charset_size) {
                    break;
                }
                indices[pos] = 0;
                if (pos == 0) {
                    // Overflow, increase length
                    if (nonce_len >= POW_MAX_NONCE_LEN) {
                         // Max nonce length reached
                         return POW_ERR_NOT_FOUND;
                    }
                    nonce_len++;
                    // Reset all to 0
                    memset(indices, 0, nonce_len);
                    break;
                }
                pos--;
            }
        }
        
        if (!solved) return POW_ERR_NOT_FOUND;
    }

    res->count = c->num_inputs;
    return POW_OK;
}
