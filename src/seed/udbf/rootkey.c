#include "rootkey.h"
#include "udbf.h"
#include "../drbg/drbg.h"
#include "../../PQCrypto/common/hkdf/hkdf.h"
#include <string.h>

/*
 * Root-Key Orchestrator implementation.
 *
 * For ROOTKEY_MODE_OSRNG we use the OS-native entropy source directly
 * without going through the DRBG, so a platform shim is needed here.
 */

/* ---- OS entropy shim ---------------------------------------------------- */

#if defined(_WIN32) || defined(_WIN64)
# include <windows.h>
BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
static int _os_random(uint8_t *buf, size_t len)
{
    return SystemFunction036(buf, (ULONG)len) ? 0 : -1;
}
#else
# include <stdio.h>
static int _os_random(uint8_t *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
}
#endif

/* ---- Module-private global DRBG ----------------------------------------- */

static DRBG_CTX s_global_drbg;
static int      s_drbg_seeded = 0;

/* Lazily seed the DRBG from OS entropy on first use in DRBG mode */
static int _ensure_drbg(void)
{
    if (s_drbg_seeded) return 0;

    uint8_t entropy[48];
    if (_os_random(entropy, sizeof(entropy)) != 0) return -1;

    drbg_init(&s_global_drbg, entropy, sizeof(entropy));

    volatile uint8_t *p = (volatile uint8_t *)entropy;
    for (size_t i = 0; i < sizeof(entropy); i++) p[i] = 0;

    s_drbg_seeded = 1;
    return 0;
}

/* ---- Public API ---------------------------------------------------------- */

int rootkey_get(rootkey_mode_t  mode,
                const char     *label,
                const uint8_t  *seed,
                size_t          seed_len,
                uint8_t        *out,
                size_t          out_len)
{
    /* Sanitise output buffer first — never leave it in ambiguous state */
    if (out && out_len > 0) memset(out, 0, out_len);
    if (!out || out_len == 0) return -1;
    if (!label || label[0] == '\0') return -1;

    switch (mode) {
    /* ---------------------------------------------------------------------- */
    case ROOTKEY_MODE_UDBF: {
        udbf_result_t r = udbf_read(label, out, out_len);
        if (r != UDBF_OK) {
            return (int)r;  /* negative UDBF error code, never fall through   */
        }
        return 0;
    }

    /* ---------------------------------------------------------------------- */
    case ROOTKEY_MODE_SEED: {
        if (!seed || seed_len == 0) return -1;

        size_t label_len = 0;
        while (label[label_len]) label_len++;

        /* HKDF(no-salt, IKM=seed, info=label) → out */
        hkdf(NULL, 0,
             seed, seed_len,
             (const uint8_t *)label, label_len,
             out, out_len);
        return 0;
    }

    /* ---------------------------------------------------------------------- */
    case ROOTKEY_MODE_DRBG: {
        if (_ensure_drbg() != 0) return -1;
        return drbg_generate(&s_global_drbg, out, out_len);
    }

    /* ---------------------------------------------------------------------- */
    case ROOTKEY_MODE_OSRNG: {
        return _os_random(out, out_len);
    }

    /* ---------------------------------------------------------------------- */
    default:
        return -1;
    }
}
