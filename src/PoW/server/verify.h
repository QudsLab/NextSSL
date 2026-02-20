#ifndef POW_SERVER_VERIFY_H
#define POW_SERVER_VERIFY_H

#include "../core/pow_types.h"

int pow_server_verify_solution(
    POWChallenge* challenge,
    POWSolution* solution,
    bool* out_valid
);

#endif // POW_SERVER_VERIFY_H
