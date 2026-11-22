/* NextSSL compat (not upstream), MSVC targets only. word.h allocates with posix_memalign and the callers
 * release with free(), so _aligned_malloc (needs _aligned_free) cannot stand in. The Windows x64 heap
 * returns 16-byte aligned blocks, which covers big_register_t on this build (SSE2, 16 bytes); a larger
 * alignment is refused with EINVAL instead of being ignored. */
#ifndef NEXTSSL_POSIX_MEMALIGN_H
#define NEXTSSL_POSIX_MEMALIGN_H
#include <errno.h>
#include <stdlib.h>
static int posix_memalign(void **out, size_t alignment, size_t size) {
    void *p;
    *out = NULL;
    if (alignment > 16) return EINVAL;
    p = malloc(size ? size : 1);
    if (!p) return ENOMEM;
    *out = p;
    return 0;
}
/* BSD fixed-width names used by intrinsics.h/word.h (glibc and Darwin have them, MSVC does not). */
#include <stdint.h>
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;
#endif
