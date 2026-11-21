/* Generated shim (not crypto): includes the verbatim upstream C++ sources into one translation unit,
 * inside a private namespace, and exports a single extern "C" entry point (0 on success). */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#endif
#if defined(__GLIBC__)
#include <endian.h>
#endif

namespace nextssl_battcrypt_phc {
#include "upstream/sha512.cpp"
#include "upstream/blowfish.cpp"
#include "upstream/battcrypt.cpp"
}  // namespace nextssl_battcrypt_phc

extern "C" int nextssl__battcrypt_phc__derive(const void *pw, size_t pwlen, const void *salt, size_t saltlen,
                                       uint32_t t_cost, uint32_t m_cost, void *out, size_t outlen) {
    int rc = nextssl_battcrypt_phc::PHS(out, outlen, pw, pwlen, salt, saltlen, t_cost, m_cost);
    return (rc == 0) ? 0 : -1;
}
