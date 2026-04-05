/* pow_challenge.h — server-side challenge generation */
#ifndef POW_CHALLENGE_H
#define POW_CHALLENGE_H

#include "../core/pow_types.h"

/* Generate a new PoW challenge.
 * algorithm_id must be in canonical hyphen-form (e.g. "sha3-256").
 * Returns 0 on success, negative on error:
 *   -1  bad args
 *   -2  WU exceeds config->max_wu_per_challenge
 *   -3  algorithm not found in dispatcher
 *   -4  DHCM calculation failed
 */
int pow_server_generate_challenge(
    const pow_config_t *config,
    const char         *algorithm_id,
    const uint8_t      *context,
    size_t              context_len,
    uint32_t            difficulty_bits,
    pow_challenge_t    *out
);

#endif /* POW_CHALLENGE_H */
