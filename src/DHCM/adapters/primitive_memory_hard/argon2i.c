#include <stdint.h>
#include <stddef.h>

#define ARGON2_BLAKE2B_COST 800

uint64_t dhcm_argon2i_mu(uint32_t m_cost) {
    return m_cost;
}

uint64_t dhcm_argon2i_wu(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism) {
    return (uint64_t)t_cost * m_cost * parallelism * ARGON2_BLAKE2B_COST;
}
