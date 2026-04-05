/* crc32.c — CRC-32 (ISO 3309 / IEEE 802.3)
 *
 * Table built once at first use.  Uses polynomial 0xEDB88320
 * (reflected representation of 0x04C11DB7).
 *
 * Thread-safety: init_table() may race on first call in multi-threaded code.
 * Call crc32_compute/crc32_update from any thread after the first call has
 * completed (e.g. during program initialisation while still single-threaded).
 * Adding a mutex here is not worth the overhead for a utility function; if
 * the platform has __attribute__((constructor)) or a once-init primitive, the
 * caller can call crc32_update(crc32_init(), NULL, 0) to prime the table.
 */
#include "crc32.h"
#include <string.h>

/* ---- lazy table ---------------------------------------------------------- */

static uint32_t s_table[256];
static int      s_table_ready = 0;

static void build_table(void)
{
    for (unsigned n = 0; n < 256; n++) {
        uint32_t c = (uint32_t)n;
        for (int k = 0; k < 8; k++) {
            if (c & 1u)
                c = 0xEDB88320u ^ (c >> 1);
            else
                c >>= 1;
        }
        s_table[n] = c;
    }
    s_table_ready = 1;
}

/* ---- public API ---------------------------------------------------------- */

uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len)
{
    if (!s_table_ready) build_table();

    /* Allow len == 0 with data == NULL (no-op) */
    if (!data || len == 0) return crc;

    while (len--) {
        crc = s_table[(crc ^ *data++) & 0xFF] ^ (crc >> 8);
    }
    return crc;
}

uint32_t crc32_compute(const uint8_t *data, size_t len)
{
    return crc32_final(crc32_update(crc32_init(), data, len));
}
