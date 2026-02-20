#ifndef POW_SERVER_CHALLENGE_H
#define POW_SERVER_CHALLENGE_H

#include "../core/pow_types.h"

int pow_server_generate_challenge(
    POWConfig* config,
    const char* algorithm_id,
    const uint8_t* context_data,
    size_t context_len,
    uint32_t difficulty_bits,
    POWChallenge* out_challenge
);

#endif // POW_SERVER_CHALLENGE_H
