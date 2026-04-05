/* pow_solver.h — client-side challenge parsing and solving */
#ifndef POW_SOLVER_H
#define POW_SOLVER_H

#include "../core/pow_types.h"

/* Parse a base64-encoded challenge string.
 * Returns 0 on success:
 *   -1  bad args
 *   -2  decode/parse failed
 *   -3  unsupported version
 *   -4  algorithm not registered in dispatcher
 */
int pow_client_parse_challenge(
    const char      *challenge_b64,
    pow_challenge_t *out
);

/* Solve a challenge by brute-force nonce search.
 * Input fed to hash: context || sprintf(nonce) as decimal ASCII string.
 * Returns 0 on success:
 *   -1  bad args
 *   -2  no solution found (nonce space exhausted)
 *   -3  hash error
 *   -4  algorithm not registered
 *   -5  context too large
 */
int pow_client_solve(
    const pow_challenge_t *challenge,
    pow_solution_t        *out
);

#endif /* POW_SOLVER_H */
