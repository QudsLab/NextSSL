#ifndef NEXTSSL_RANDOMBYTES_H
#define NEXTSSL_RANDOMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

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
 * GAP-5: Explicit OS-RNG opt-in (debug builds only).
 * Call once before using randombytes() without prior seeding.
 * See randombytes.c for rationale.
 */
#ifndef NDEBUG
void pqc_randombytes_use_os_rng(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_RANDOMBYTES_H */
