/* Generated shim (not crypto): includes the verbatim upstream C++ sources into one translation unit,
 * inside a private namespace, and exports a single extern "C" entry point (0 on success). */
#include <stddef.h>
#include <stdint.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cassert>

namespace nextssl_gambit_phc {
#include NEXTSSL_GAMBIT_KECCAK /* upstream/keccak.cpp with buffer_xor's void* steps via char* (build.rs) */
#include "upstream/gambit.cpp"
}  // namespace nextssl_gambit_phc

extern "C" int nextssl__gambit_phc__derive(const void *pw, size_t pwlen, const void *salt, size_t saltlen,
                                       uint32_t t_cost, uint32_t m_cost, void *out, size_t outlen) {
    int rc = nextssl_gambit_phc::PHS(out, outlen, pw, pwlen, salt, saltlen, t_cost, m_cost);
    return (rc == 0) ? 0 : -1;
}
