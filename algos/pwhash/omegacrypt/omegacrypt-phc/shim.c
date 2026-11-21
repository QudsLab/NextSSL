/* Generated shim (not crypto): calls the upstream PHC entry point PHS and reports 0 on success. */
#include <stddef.h>
#include <stdint.h>
#include "phs.h"

int nextssl__omegacrypt_phc__derive(const void *pw, size_t pwlen, const void *salt, size_t saltlen,
                            uint32_t t_cost, uint32_t m_cost, void *out, size_t outlen) {
    int rc = PHS(out, outlen, pw, pwlen, salt, saltlen, t_cost, m_cost);
    return (rc == 0) ? 0 : -1;
}
