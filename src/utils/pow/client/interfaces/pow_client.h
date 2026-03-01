#ifndef nextssl_POW_CLIENT_H
#define nextssl_POW_CLIENT_H

#include "pow_protocol.h"
#include "pow_hash_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Safety Configuration (Defaults)
#define CLIENT_MAX_MEMORY_KB (64 * 1024) // 64MB
#define CLIENT_MAX_TIME_MS 10000 // 10 sec
#define CLIENT_MAX_BATCH 4

// Check if a challenge is safe to execute
// Returns POW_OK if safe, or POW_ERR_SAFETY_VIOLATION / POW_ERR_UNKNOWN_ALGO
PoWError pow_client_check_safety(const PoWChallenge *c);

// Solve a challenge
// Returns POW_OK on success (nonce found), POW_ERR_TIMEOUT, or other error.
// result_nonce must be large enough (POW_MAX_NONCE_LEN)
// If batch inputs, result_nonce is for the LAST input? Or we need multiple results?
// For batch, we probably want an array of results or a callback.
// For simplicity here, let's assume we return the nonce for the FIRST input or handle batch logic inside.
// Protocol says "Return Nonce". If multiple inputs, do we return multiple nonces?
// "Example B: Returns a list of nonces".
// So we need an output struct.
typedef struct {
    uint8_t nonces[POW_MAX_INPUTS][POW_MAX_NONCE_LEN];
    size_t nonce_lens[POW_MAX_INPUTS];
    uint32_t count;
} PoWResult;

PoWError pow_client_solve(const PoWChallenge *c, PoWResult *res);
PoWError pow_client_hash(PoWAlgorithm algo, const PoWHashArgs *args, char *error_msg, size_t error_len, char *warning_msg, size_t warning_len);

#ifdef __cplusplus
}
#endif

#endif // nextssl_POW_CLIENT_H
