/* dhcm_difficulty.c */
#include "dhcm_difficulty.h"
#include "dhcm_math.h"

double dhcm_expected_trials(DHCMDifficultyModel model, uint32_t target_zeros) {
    switch (model) {
        case DHCM_DIFFICULTY_NONE:
            return 1.0;
        case DHCM_DIFFICULTY_TARGET_BASED:
            /* Each bit halves the probability of success: E[N] = 2^z */
            return dhcm_pow2(target_zeros);
        case DHCM_DIFFICULTY_ITERATION_BASED:
            /* Cost is embedded in the per-eval WU; only one evaluation needed */
            return 1.0;
        default:
            return 1.0;
    }
}
