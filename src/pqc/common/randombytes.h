#ifndef NEXTSSL_RANDOMBYTES_H
#define NEXTSSL_RANDOMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "nextssl_export.h"

#ifdef _WIN32
/* Load size_t on windows */
#include <crtdefs.h>
#else
#include <unistd.h>
#endif /* _WIN32 */

/*
 * Write `n` bytes of high quality random bytes to `buf`
 */
#define randombytes     NEXTSSL_randombytes
int randombytes(uint8_t *output, size_t n);

/*
 * Explicit OS-RNG opt-in helper.
 * Call before using randombytes() without prior DRBG/UDBF seeding.
 */
NEXTSSL_API void pqc_randombytes_use_os_rng(void);

/*
 * Enable or disable the direct OS-RNG fallback path.
 * Pass non-zero to allow randombytes() to use the OS RNG when no DRBG seed
 * or UDBF source has been configured yet.
 */
NEXTSSL_API int pqc_randombytes_set_mode(int unsafe);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_RANDOMBYTES_H */
