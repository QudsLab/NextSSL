/* udbf.c — Test Vector Override Implementation
 *
 * Simple key-value store for test vectors. Global state (not thread-safe).
 */
#include "udbf.h"
#include "../../common/secure_zero.h"
#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Global UDBF state
 * -------------------------------------------------------------------------*/

#define UDBF_MAX_SIZE (1u << 20)  /* 1 MB max */

static struct {
    uint8_t *data;          /* Allocated UDBF buffer */
    size_t data_len;        /* Total length */
    int is_loaded;          /* 1 if data is loaded, 0 otherwise */
} g_udbf = { NULL, 0, 0 };

/* -------------------------------------------------------------------------
 * UDBF Format Helper Functions
 * -------------------------------------------------------------------------*/

/* Helper: Read little-endian uint32 from buffer */
static uint32_t read_le32(const uint8_t *buf)
{
    return ((uint32_t)buf[0]) |
           (((uint32_t)buf[1]) << 8) |
           (((uint32_t)buf[2]) << 16) |
           (((uint32_t)buf[3]) << 24);
}

/* -------------------------------------------------------------------------
 * udbf_feed — Load UDBF data
 * -------------------------------------------------------------------------*/
int udbf_feed(const uint8_t *data, size_t len)
{
    if (!data || len < 5 || len > UDBF_MAX_SIZE) {
        return UDBF_ERR_TOO_LARGE;
    }

    if (g_udbf.is_loaded) {
        return UDBF_ERR_ALREADY_LOADED;
    }

    /* Allocate and copy UDBF data */
    g_udbf.data = (uint8_t *)malloc(len);
    if (!g_udbf.data) {
        return UDBF_ERR_TOO_LARGE;
    }

    memcpy(g_udbf.data, data, len);
    g_udbf.data_len = len;
    g_udbf.is_loaded = 1;

    return UDBF_OK;
}

/* -------------------------------------------------------------------------
 * udbf_read — Extract labeled value from UDBF
 * -------------------------------------------------------------------------
 *
 * UDBF Format:
 *   Offset  | Type     | Description
 *   --------+----------+------------------------------------
 *   0-3     | uint32LE | Total UDBF size
 *   4+      | entries  | Variable-length entries
 *
 * Each entry:
 *   Offset  | Type     | Description
 *   --------+----------+------------------------------------
 *   0       | uint8    | Label length (1-255)
 *   1-N     | bytes    | Label string
 *   N+1-N+4 | uint32LE | Value length
 *   N+5-... | bytes    | Value data
 */
int udbf_read(const char *label, uint8_t *out, size_t olen)
{
    size_t label_len;
    size_t pos;
    uint8_t entry_label_len;
    uint32_t value_len;
    int match;

    if (!label || !out || olen == 0) {
        return UDBF_ERR_NO_DATA;
    }

    if (!g_udbf.is_loaded) {
        return UDBF_ERR_NO_DATA;
    }

    label_len = strlen(label);

    /* Skip header (4 bytes) */
    pos = 4;

    /* Iterate through entries */
    while (pos < g_udbf.data_len) {
        if (pos + 1 > g_udbf.data_len) {
            break;  /* Malformed entry */
        }

        /* Read label length */
        entry_label_len = g_udbf.data[pos];
        pos++;

        /* Check bounds */
        if (pos + entry_label_len + 4 > g_udbf.data_len) {
            break;  /* Malformed entry */
        }

        /* Try to match label */
        match = (entry_label_len == label_len &&
                 memcmp(&g_udbf.data[pos], label, label_len) == 0);

        pos += entry_label_len;

        /* Read value length */
        value_len = read_le32(&g_udbf.data[pos]);
        pos += 4;

        /* Check value bounds */
        if (pos + value_len > g_udbf.data_len) {
            break;  /* Malformed entry */
        }

        if (match) {
            /* Found matching label */
            if (value_len < olen) {
                /* Not enough bytes provided */
                return UDBF_ERR_TOO_LARGE;
            }

            /* Copy value to output */
            memcpy(out, &g_udbf.data[pos], olen);
            return (int)olen;
        }

        /* Move to next entry */
        pos += value_len;
    }

    /* Label not found */
    return UDBF_ERR_LABEL_NOT_FOUND;
}

/* -------------------------------------------------------------------------
 * seed_udbf_is_active — Check if UDBF is loaded (called by seed_core)
 * -------------------------------------------------------------------------*/
int seed_udbf_is_active(void)
{
    return g_udbf.is_loaded;
}

/* -------------------------------------------------------------------------
 * udbf_wipe — Clear UDBF data
 * -------------------------------------------------------------------------*/
void udbf_wipe(void)
{
    if (g_udbf.data) {
        secure_zero(g_udbf.data, g_udbf.data_len);
        free(g_udbf.data);
        g_udbf.data = NULL;
    }

    g_udbf.data_len = 0;
    g_udbf.is_loaded = 0;
}
