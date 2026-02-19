#ifndef DHCM_CORE_H
#define DHCM_CORE_H

#include "dhcm_types.h"

// Initialize DHCM result structure
void dhcm_init_result(DHCMResult *result);

// Core calculation function
int dhcm_core_calculate(const DHCMParams *params, DHCMResult *result);

// Get algorithm name
const char* dhcm_get_algorithm_name(DHCMAlgorithm algo);

#endif // DHCM_CORE_H
