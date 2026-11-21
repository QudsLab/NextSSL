/* Generated shim (not crypto): calls the upstream PHC entry point PHS and reports 0 on success. */
#include <stddef.h>
#include <stdint.h>
#include "lanarea.h"
/* libb2 normally links blake2b() through blake2-dispatch.c; with SUFFIX=_ref blake2b-ref.c defines blake2b_ref(), forward to it. */
extern int blake2b_ref(uint8_t *out, const void *in, const void *key, size_t outlen, size_t inlen, size_t keylen);
int blake2b(uint8_t *out, const void *in, const void *key, size_t outlen, size_t inlen, size_t keylen) {
    return blake2b_ref(out, in, key, outlen, inlen, keylen);
}
int nextssl__lanarea_phc__derive(const void *pw, size_t pwlen, const void *salt, size_t saltlen,
                            uint32_t t_cost, uint32_t m_cost, void *out, size_t outlen) {
    int rc = PHS(out, outlen, pw, pwlen, salt, saltlen, t_cost, m_cost);
    return (rc == 0) ? 0 : -1;
}
