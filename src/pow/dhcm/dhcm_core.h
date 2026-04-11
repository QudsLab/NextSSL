/* dhcm_core.h — DHCM core cost oracle */
#ifndef DHCM_CORE_H
#define DHCM_CORE_H

#include "dhcm_types.h"

/* Initialise a DHCMResult to zero-state defaults. */
void dhcm_result_init(DHCMResult *r);

/* Calculate WU and MU for an algorithm at a given difficulty.
 * Returns 0 on success, -1 on NULL args, -2 on unknown algorithm.
 * Fills all fields of *result. */
int dhcm_core_calculate(const DHCMParams *params, DHCMResult *result);

/* Map a DHCMAlgorithm to its canonical hyphen-form name string.
 * Returns NULL for DHCM_ALGO_UNKNOWN. */
const char *dhcm_algo_name(DHCMAlgorithm algo);

/* Map a canonical hyphen-form name to its DHCMAlgorithm enum value.
 * Returns DHCM_ALGO_UNKNOWN if the name is not recognised. */
DHCMAlgorithm dhcm_algo_from_name(const char *name);

/* Convenience: calculate cost for a named algorithm at given difficulty.
 * Selects the correct DHCMDifficultyModel automatically.
 * Returns 0 on success, -1 on NULL args, -2 on unknown algorithm. */
int dhcm_cost_for_name(const char *algo_name, uint32_t difficulty_bits,
                       size_t input_size, DHCMResult *result);

#endif /* DHCM_CORE_H */
