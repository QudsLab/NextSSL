#if defined(_WIN32) || defined(_WIN64)
#   include <windows.h>
#   include <bcrypt.h>
#   pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
#   include <sys/random.h>
#   include <errno.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#   include <stdlib.h>  /* arc4random_buf */
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rng.h"

int rng_fill(uint8_t *out, size_t len) {
    if (!out || len == 0) return -1;

#if defined(_WIN32) || defined(_WIN64)
    NTSTATUS status = BCryptGenRandom(NULL, (PUCHAR)out, (ULONG)len,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(status) ? 0 : -1;

#elif defined(__linux__)
    size_t done = 0;
    while (done < len) {
        ssize_t r = getrandom(out + done, len - done, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        done += (size_t)r;
    }
    return 0;

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(out, len);
    return 0;

#else
#   error "rng_fill: unsupported platform — add a platform case"
    return -1;
#endif
}

int rng_uint32(uint32_t *out) {
    if (!out) return -1;
    return rng_fill((uint8_t *)out, sizeof(uint32_t));
}

int rng_uint64(uint64_t *out) {
    if (!out) return -1;
    return rng_fill((uint8_t *)out, sizeof(uint64_t));
}
