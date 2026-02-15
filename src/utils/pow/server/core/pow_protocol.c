#include "pow_protocol.h"
#include <stdlib.h>

void pow_challenge_free(PoWChallenge *challenge) {
    if (!challenge) return;
    for (uint32_t i = 0; i < challenge->num_inputs; i++) {
        if (challenge->inputs[i]) {
            free(challenge->inputs[i]);
            challenge->inputs[i] = NULL;
        }
    }
    // Ranges and Targets are fixed arrays in struct, no free needed
}
