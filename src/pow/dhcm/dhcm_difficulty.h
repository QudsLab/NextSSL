/* dhcm_difficulty.h — expected trial count from difficulty model */
#ifndef DHCM_DIFFICULTY_H
#define DHCM_DIFFICULTY_H

#include "dhcm_types.h"

/* Returns E[N]: expected number of hash evaluations needed to find a solution.
 * For target-based PoW: E[N] = 2^target_zeros.
 * For iteration-based: E[N] = 1.0 (cost is in the per-eval WU). */
double dhcm_expected_trials(DHCMDifficultyModel model, uint32_t target_zeros);

#endif /* DHCM_DIFFICULTY_H */
