#include "pow_protocol.h"
#include "../../../encoding/base64.h"
#include <string.h>
#include <stdlib.h>

// Helper macros for serialization (Little Endian)
#define WR_U8(p, v) do { *(uint8_t*)(p) = (v); (p) += 1; } while(0)
#define WR_U16(p, v) do { *(uint8_t*)(p) = (v) & 0xFF; *((uint8_t*)(p)+1) = ((v)>>8) & 0xFF; (p) += 2; } while(0)
#define WR_U32(p, v) do { *(uint8_t*)(p) = (v) & 0xFF; *((uint8_t*)(p)+1) = ((v)>>8) & 0xFF; *((uint8_t*)(p)+2) = ((v)>>16) & 0xFF; *((uint8_t*)(p)+3) = ((v)>>24) & 0xFF; (p) += 4; } while(0)
#define WR_U64(p, v) do { WR_U32(p, (uint32_t)(v)); WR_U32(p, (uint32_t)((v)>>32)); } while(0)
#define WR_BYTES(p, buf, len) do { memcpy(p, buf, len); (p) += (len); } while(0)

#define RD_U8(p, v) do { (v) = *(uint8_t*)(p); (p) += 1; } while(0)
#define RD_U16(p, v) do { (v) = (*(uint8_t*)(p)) | (*((uint8_t*)(p)+1) << 8); (p) += 2; } while(0)
#define RD_U32(p, v) do { (v) = (*(uint8_t*)(p)) | (*((uint8_t*)(p)+1) << 8) | (*((uint8_t*)(p)+2) << 16) | (*((uint8_t*)(p)+3) << 24); (p) += 4; } while(0)
#define RD_U64(p, v) do { uint32_t l, h; RD_U32(p, l); RD_U32(p, h); (v) = ((uint64_t)h << 32) | l; } while(0)

// Safe Read Check
#define CHECK_AVAIL(len, needed) do { if ((len) < (needed)) { pow_challenge_free(out_c); return POW_ERR_INVALID_FORMAT; } } while(0)

int pow_challenge_encode(const PoWChallenge *c, char *out_b64, size_t max_len) {
    if (!c || !out_b64) return -1;
    
    // 1. Calculate binary size
    size_t bin_size = 4 + 1 + 1; // Ver, Algo, NumInputs
    for (uint32_t i = 0; i < c->num_inputs; i++) {
        bin_size += 2 + c->input_lens[i];
    }
    bin_size += 1; // NumTargets
    for (uint32_t i = 0; i < c->num_targets; i++) {
        bin_size += 1 + c->targets[i].prefix_len + 4 + 8; // PreLen, Pre, Diff, Threshold
    }
    bin_size += 1 + c->num_ranges * 2; // NumRanges, Min/Max
    bin_size += 8 + 4 + 4;
    bin_size += 4 + 4 + 4 + 4 + 4;
    
    uint8_t *bin = (uint8_t*)malloc(bin_size);
    if (!bin) return -1;
    
    // 2. Serialize
    uint8_t *p = bin;
    WR_U32(p, c->version);
    WR_U8(p, (uint8_t)c->algo);
    WR_U8(p, (uint8_t)c->num_inputs);
    for (uint32_t i = 0; i < c->num_inputs; i++) {
        WR_U16(p, (uint16_t)c->input_lens[i]);
        WR_BYTES(p, c->inputs[i], c->input_lens[i]);
    }
    WR_U8(p, (uint8_t)c->num_targets);
    for (uint32_t i = 0; i < c->num_targets; i++) {
        WR_U8(p, c->targets[i].prefix_len);
        if (c->targets[i].prefix_len > 0) {
            WR_BYTES(p, c->targets[i].prefix, c->targets[i].prefix_len);
        }
        WR_U32(p, c->targets[i].difficulty);
        WR_U64(p, c->targets[i].target_threshold_u64);
    }
    WR_U8(p, (uint8_t)c->num_ranges);
    for (uint32_t i = 0; i < c->num_ranges; i++) {
        WR_U8(p, c->ranges[i].min_char);
        WR_U8(p, c->ranges[i].max_char);
    }
    WR_U64(p, c->max_tries);
    WR_U32(p, c->max_time_ms);
    WR_U32(p, c->max_memory_kb);
    WR_U32(p, c->hash_out_len);
    WR_U32(p, c->argon2_t_cost);
    WR_U32(p, c->argon2_m_cost_kb);
    WR_U32(p, c->argon2_parallelism);
    WR_U32(p, c->argon2_encoded_len);
    
    // 3. Encode to Base64
    size_t required_len = base64_encoded_len(bin_size);
    if (required_len > max_len) {
        free(bin);
        return -1;
    }
    
    int res = base64_encode(bin, bin_size, out_b64, max_len);
    free(bin);
    return res; // 0 on success, -1 on failure
}

int pow_challenge_decode(const char *b64_str, PoWChallenge *out_c) {
    if (!b64_str || !out_c) return -1;
    memset(out_c, 0, sizeof(PoWChallenge));
    
    size_t b64_len = strlen(b64_str);
    size_t bin_len = base64_decoded_len(b64_len);
    uint8_t *bin = (uint8_t*)malloc(bin_len);
    if (!bin) return -1;
    
    int decoded_len = base64_decode(b64_str, b64_len, bin, bin_len);
    if (decoded_len < 0) {
        free(bin);
        return POW_ERR_INVALID_FORMAT;
    }
    
    // Deserialize
    uint8_t *p = bin;
    size_t len = (size_t)decoded_len;
    
    // Use macro CHECK_AVAIL which frees out_c on error
    CHECK_AVAIL(len, 4 + 1 + 1);
    RD_U32(p, out_c->version);
    uint8_t algo_u8; RD_U8(p, algo_u8); out_c->algo = (PoWAlgorithm)algo_u8;
    
    uint8_t num_inputs; RD_U8(p, num_inputs);
    if (num_inputs > POW_MAX_INPUTS) { free(bin); pow_challenge_free(out_c); return POW_ERR_INVALID_FORMAT; }
    out_c->num_inputs = num_inputs;
    
    for (uint32_t i = 0; i < num_inputs; i++) {
        CHECK_AVAIL(len, 2);
        uint16_t ilen; RD_U16(p, ilen);
        CHECK_AVAIL(len, ilen);
        out_c->inputs[i] = (uint8_t*)malloc(ilen);
        if (!out_c->inputs[i]) { free(bin); pow_challenge_free(out_c); return POW_ERR_MEMORY; }
        memcpy(out_c->inputs[i], p, ilen);
        out_c->input_lens[i] = ilen;
        p += ilen; len -= ilen;
    }
    
    CHECK_AVAIL(len, 1);
    uint8_t num_targets; RD_U8(p, num_targets);
    if (num_targets > POW_MAX_TARGETS) { free(bin); pow_challenge_free(out_c); return POW_ERR_INVALID_FORMAT; }
    out_c->num_targets = num_targets;
    
    for (uint32_t i = 0; i < num_targets; i++) {
        CHECK_AVAIL(len, 1);
        uint8_t pre_len; RD_U8(p, pre_len);
        if (pre_len > POW_MAX_PREFIX_LEN) { free(bin); pow_challenge_free(out_c); return POW_ERR_INVALID_FORMAT; }
        out_c->targets[i].prefix_len = pre_len;
        
        CHECK_AVAIL(len, pre_len + 4 + 8);
        if (pre_len > 0) {
            memcpy(out_c->targets[i].prefix, p, pre_len);
            p += pre_len;
        }
        RD_U32(p, out_c->targets[i].difficulty);
        RD_U64(p, out_c->targets[i].target_threshold_u64);
    }
    
    CHECK_AVAIL(len, 1);
    uint8_t num_ranges; RD_U8(p, num_ranges);
    if (num_ranges > POW_MAX_RANGES) { free(bin); pow_challenge_free(out_c); return POW_ERR_INVALID_FORMAT; }
    out_c->num_ranges = num_ranges;
    
    CHECK_AVAIL(len, num_ranges * 2);
    for (uint32_t i = 0; i < num_ranges; i++) {
        RD_U8(p, out_c->ranges[i].min_char);
        RD_U8(p, out_c->ranges[i].max_char);
    }
    
    CHECK_AVAIL(len, 16);
    RD_U64(p, out_c->max_tries);
    RD_U32(p, out_c->max_time_ms);
    RD_U32(p, out_c->max_memory_kb);
    
    if (len >= 20) {
        RD_U32(p, out_c->hash_out_len);
        RD_U32(p, out_c->argon2_t_cost);
        RD_U32(p, out_c->argon2_m_cost_kb);
        RD_U32(p, out_c->argon2_parallelism);
        RD_U32(p, out_c->argon2_encoded_len);
    }
    
    free(bin);
    return 0;
}
