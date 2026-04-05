/* pow_verify.h — server-side solution verification */
#ifndef POW_VERIFY_H
#define POW_VERIFY_H

#include "../core/pow_types.h"
#include <stdbool.h>

/* Verify a solution against its challenge.
 * Re-hashes context||nonce and checks hash < target.
 * Also checks challenge_id match and expiry.
 * Returns 0 on success (check *out_valid for result).
 *   -1  bad args
 *   -2  challenge_id mismatch
 *   -3  algorithm not found / hash failed
 *   -4  challenge expired
 */
int pow_server_verify_solution(
    const pow_challenge_t *challenge,
    const pow_solution_t  *solution,
    bool                  *out_valid
);

#endif /* POW_VERIFY_H */
