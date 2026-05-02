/* crc64.c — CRC-64 ECMA-182
 *
 * Reflected polynomial 0xC96C5795D7870F42.
 * Table built lazily on first use (same thread-safety caveat as crc32.c).
 */
#include "crc64.h"

/* ---- lazy table ---------------------------------------------------------- */

static uint64_t s_table[256];
static int      s_table_ready = 0;

static void build_table(void)
{
    const uint64_t poly = UINT64_C(0xC96C5795D7870F42);
    for (unsigned n = 0; n < 256; n++) {
        uint64_t c = (uint64_t)n;
        for (int k = 0; k < 8; k++) {
            if (c & 1u)
                c = poly ^ (c >> 1);
            else
                c >>= 1;
        }
        s_table[n] = c;
    }
    s_table_ready = 1;
}

/* ---- public API ---------------------------------------------------------- */

uint64_t crc64_update(uint64_t crc, const uint8_t *data, size_t len)
{
    if (!s_table_ready) build_table();
    if (!data || len == 0) return crc;
    while (len--) {
        crc = s_table[(crc ^ *data++) & 0xFF] ^ (crc >> 8);
    }
    return crc;
}

uint64_t crc64_compute(const uint8_t *data, size_t len)
{
    return crc64_final(crc64_update(crc64_init(), data, len));
}
