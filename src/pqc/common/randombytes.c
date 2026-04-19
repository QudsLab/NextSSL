/*
The MIT License

Copyright (c) 2017 Daan Sprenkels <hello@dsprenkels.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "randombytes.h"
#include "../../seed/drbg/drbg.h"
#include "../../seed/udbf/udbf.h"
/*
 * rng_fill is the unified OS-random entry point for the library.
 * All native targets (Windows/Linux/macOS/BSD) are handled there so we do
 * not duplicate platform dispatch code here.
 */
#include "../../seed/rng/rng.h"
#include <assert.h>

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

static DRBG_CTX global_drbg;
static int drbg_initialized = 0;
static int g_randombytes_allow_os_rng = 0;

EXPORT void pqc_randombytes_use_os_rng(void) {
    g_randombytes_allow_os_rng = 1;
}

EXPORT int pqc_randombytes_set_mode(int unsafe) {
    g_randombytes_allow_os_rng = unsafe ? 1 : 0;
    return 0;
}

EXPORT void pqc_randombytes_seed(const uint8_t *seed, size_t seed_len) {
    drbg_init(&global_drbg, seed, seed_len);
    drbg_initialized = 1;
}

EXPORT void pqc_randombytes_reseed(const uint8_t *seed, size_t seed_len) {
    drbg_reseed(&global_drbg, seed, seed_len);
    drbg_initialized = 1;
}

/* Thin shim: route external UDBF feed through the canonical common/udbf layer */
EXPORT void pqc_set_udbf(const uint8_t *buf, size_t len) {
    udbf_feed(buf, len);
}

/* ------------------------------------------------------------------
 * Emscripten: use Node.js crypto.randomBytes (rng_fill does not cover JS/WASM)
 * ------------------------------------------------------------------ */
#if defined(__EMSCRIPTEN__)
# include <assert.h>
# include <emscripten.h>
# include <errno.h>
# include <stdbool.h>
static int randombytes_js_randombytes_nodejs(void *buf, size_t n) {
    const int ret = EM_ASM_INT({
        var crypto;
        try {
            crypto = require('crypto');
        } catch (error) {
            return -2;
        }
        try {
            writeArrayToMemory(crypto.randomBytes($1), $0);
            return 0;
        } catch (error) {
            return -1;
        }
    }, buf, n);
    switch (ret) {
    case 0:  return 0;
    case -1: errno = EINVAL; return -1;
    case -2: errno = ENOSYS; return -1;
    }
    assert(false); /* Unreachable */
}
#endif /* defined(__EMSCRIPTEN__) */

/*
 * randombytes_os -- OS entropy source.
 *
 * Native targets delegate to rng_fill() (one implementation shared with the
 * rest of the library).  Emscripten uses its own JS path because rng_fill
 * does not cover the browser/Node.js environment.
 */
static int randombytes_os(uint8_t *output, size_t n) {
#if defined(__EMSCRIPTEN__)
    return randombytes_js_randombytes_nodejs((void *)output, n);
#else
    return rng_fill(output, n);
#endif
}

int randombytes(uint8_t *output, size_t n) {
    /* UDBF path: delegate to common/udbf -- returns error on exhaustion, never zero-fills */
    if (udbf_is_active()) {
        int ret = udbf_read("randombytes", output, n);
        if (ret != 0) {
            /* UDBF_ERR_EXHAUSTED or other error -- do NOT silently fall through */
            return ret;
        }
        return 0;
    }

    if (drbg_initialized) {
        return drbg_generate(&global_drbg, output, n);
    }
    if (!g_randombytes_allow_os_rng) {
        return -1;
    }
    return randombytes_os(output, n);
}