#ifndef DHCM_API_H
#define DHCM_API_H

#include "../core/dhcm_types.h"

// DLL Export macro
#ifdef _WIN32
    #define DHCM_EXPORT __declspec(dllexport)
#else
    #define DHCM_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Main entry point for cost calculation
DHCM_EXPORT int nextssl_dhcm_calculate(const DHCMParams *params, DHCMResult *result);

// Helper to get algorithm info
DHCM_EXPORT int nextssl_dhcm_get_algorithm_info(DHCMAlgorithm algo, const char **name, uint64_t *base_wu, size_t *block_size);

// Helper for expected trials
DHCM_EXPORT double nextssl_dhcm_expected_trials(DHCMDifficultyModel model, uint32_t target_zeros);

#ifdef __cplusplus
}
#endif

#endif // DHCM_API_H
