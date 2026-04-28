/* entropy.c — OS RNG Interface (TIER 1)
 *
 * Platform-specific cryptographic RNG wrapper.
 */
#include "entropy.h"
#include <string.h>

#if defined(__EMSCRIPTEN__)
    /* WASM/Emscripten: delegate to JS crypto.getRandomValues via import */
    #include <emscripten.h>
#elif defined(_WIN32)
    #include <windows.h>
    #include <wincrypt.h>
#else
    #include <unistd.h>
    #include <sys/syscall.h>
    #include <errno.h>
#endif

/* -------------------------------------------------------------------------
 * entropy_getrandom — Platform-specific RNG
 * -------------------------------------------------------------------------*/
int entropy_getrandom(uint8_t *out, size_t out_len)
{
    if (!out || out_len == 0) {
        return -1;  /* Invalid arguments */
    }

#if defined(__EMSCRIPTEN__)
    /* WASM: crypto.getRandomValues via Emscripten JS interop */
    EM_ASM({
        var buf = new Uint8Array(Module.HEAPU8.buffer, $0, $1);
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            crypto.getRandomValues(buf);
        } else if (typeof require !== 'undefined') {
            /* Node.js */
            var nodeCrypto = require('crypto');
            var tmp = nodeCrypto.randomBytes($1);
            buf.set(tmp);
        }
    }, out, (int)out_len);
    return 0;

#elif defined(_WIN32)
    /* Windows: BCryptGenRandom */
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status;

    /* Open the default RNG algorithm */
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return -1;  /* Failed to open RNG */
    }

    /* Generate random bytes */
    status = BCryptGenRandom(hAlgorithm, out, (ULONG)out_len, 0);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    if (!BCRYPT_SUCCESS(status)) {
        return -1;  /* Failed to generate random data */
    }
    return 0;

#elif defined(__linux__)
    /* Linux: getrandom syscall */
    ssize_t result;
    size_t bytes_read = 0;
    
    while (bytes_read < out_len) {
        result = syscall(SYS_getrandom, out + bytes_read, out_len - bytes_read, 0);
        if (result < 0) {
            if (errno == EINTR) {
                continue;  /* Retry on interrupt */
            }
            return -1;  /* Failed */
        }
        bytes_read += result;
    }
    return 0;

#elif defined(__APPLE__)
    /* macOS / BSD: arc4random_buf (declared in <stdlib.h>) */
    #include <stdlib.h>
    arc4random_buf(out, out_len);
    return 0;

#else
    /* Unsupported platform */
    return -1;
#endif
}

/* -------------------------------------------------------------------------
 * entropy_available — Check RNG availability
 * -------------------------------------------------------------------------*/
int entropy_available(void)
{
#if defined(__EMSCRIPTEN__)
    return 1;  /* WASM: crypto.getRandomValues always present in browsers/Node */
#elif defined(_WIN32)
    return 1;  /* Windows: BCryptGenRandom always available */
#elif defined(__linux__) || defined(__APPLE__)
    return 1;  /* Linux: getrandom / macOS: arc4random_buf available */
#else
    return 0;  /* Unknown platform */
#endif
}
