#include <stdint.h>
#include <stddef.h>

#define ARGON2_BLAKE2B_COST 800  // BLAKE2b cost per block
#define ARGON2_BLOCK_SIZE 1024   // 1 KB blocks

// Shared MU calculation for all Argon2 variants
uint64_t dhcm_argon2_mu(uint32_t m_cost) {
    return m_cost; // Direct memory cost in KB
}

uint64_t dhcm_argon2id_wu(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism) {
    // Each iteration processes m_cost blocks
    // Each block involves BLAKE2b compression
    // WU = t_cost * m_cost * parallelism * Cost_per_block
    
    return (uint64_t)t_cost * m_cost * parallelism * ARGON2_BLAKE2B_COST;
}
