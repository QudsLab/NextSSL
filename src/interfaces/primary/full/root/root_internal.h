/**
 * @file root/root_internal.h
 * @brief Internal helpers shared across root sub-modules (NOT public API).
 *
 * Include only from root/ implementation (.c) files, never from outside.
 */

#ifndef NEXTSSL_ROOT_INTERNAL_H
#define NEXTSSL_ROOT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif
#include "../../../../config.h"  /* NEXTSSL_API */

/* -------------------------------------------------------------------------
 * CSPRNG helper — fills buf with len cryptographically random bytes.
 * Returns 0 on success, -1 on failure.
 * Defined static inline so each TU gets its own copy without link conflict.
 * ---------------------------------------------------------------------- */
#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
static inline int _root_rand(uint8_t *buf, size_t len) {
    return BCryptGenRandom(NULL, buf, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
}
#elif defined(__APPLE__)
#  include <sys/random.h>
static inline int _root_rand(uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;
        if (getentropy((char *)buf + off, chunk) != 0) return -1;
        off += chunk;
    }
    return 0;
}
#else
#  include <sys/random.h>
static inline int _root_rand(uint8_t *buf, size_t len) {
    return getrandom(buf, len, 0) == (ssize_t)len ? 0 : -1;
}
#endif

#endif /* NEXTSSL_ROOT_INTERNAL_H */
