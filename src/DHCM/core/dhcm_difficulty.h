#ifndef DHCM_DIFFICULTY_H
#define DHCM_DIFFICULTY_H

#include "dhcm_types.h"

// Calculate expected trials for a given difficulty model
double dhcm_calculate_expected_trials(DHCMDifficultyModel model, uint32_t target_zeros);

#endif // DHCM_DIFFICULTY_H
