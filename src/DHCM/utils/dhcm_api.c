#include "dhcm_api.h"
#include "../core/dhcm_core.h"
#include "../core/dhcm_difficulty.h"

int leyline_dhcm_calculate(const DHCMParams *params, DHCMResult *result) {
    return dhcm_core_calculate(params, result);
}

int leyline_dhcm_get_algorithm_info(DHCMAlgorithm algo, const char **name, uint64_t *base_wu, size_t *block_size) {
    // This is a simplified version. Real implementation might need lookup tables.
    // For now, we reuse core calculate to get name.
    DHCMResult res;
    DHCMParams p = {0};
    p.algorithm = algo;
    
    if (dhcm_core_calculate(&p, &res) != 0) {
        return -1;
    }
    
    if (name) *name = res.algorithm_name;
    // Base WU and block size are internal constants, we might need a separate lookup 
    // or expose them via core if strictly needed.
    // For now, returning 0/0 is acceptable or we can implement full lookup table later.
    if (base_wu) *base_wu = 0; 
    if (block_size) *block_size = 0;
    
    return 0;
}

double leyline_dhcm_expected_trials(DHCMDifficultyModel model, uint32_t target_zeros) {
    return dhcm_calculate_expected_trials(model, target_zeros);
}
