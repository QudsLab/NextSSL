#include "dhcm_difficulty.h"
#include "dhcm_math.h"
#include <math.h>

double dhcm_calculate_expected_trials(DHCMDifficultyModel model, uint32_t target_zeros) {
    switch (model) {
        case DHCM_DIFFICULTY_NONE:
            return 1.0;
            
        case DHCM_DIFFICULTY_TARGET_BASED:
            // E[N] = 2^z
            return dhcm_pow2(target_zeros);
            
        case DHCM_DIFFICULTY_ITERATION_BASED:
            // Iteration-based difficulty increases the cost per trial,
            // not the number of trials.
            return 1.0;
            
        default:
            return 1.0;
    }
}
