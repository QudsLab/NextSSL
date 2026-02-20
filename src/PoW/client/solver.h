#ifndef POW_CLIENT_SOLVER_H
#define POW_CLIENT_SOLVER_H

#include "../core/pow_types.h"

int pow_client_parse_challenge(
    const char* challenge_base64,
    POWChallenge* out_challenge
);

int pow_client_solve(
    POWChallenge* challenge,
    POWSolution* out_solution
);

#endif // POW_CLIENT_SOLVER_H
