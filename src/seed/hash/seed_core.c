/* seed_core.c — TIER 2 Main Dispatcher Implementation */
#include "seed_core.h"
#include "ctr_mode.h"
#include "hash_internal.h"
#include "hash_registry.h"
#include "../udbf/udbf.h"
#include <string.h>

/* -------------------------------------------------------------------------
 * seed_hash_derive — TIER 2 dispatcher with TIER 3 override check
 * -------------------------------------------------------------------------*/
int seed_hash_derive(const seed_hash_config_t *cfg,
                     const uint8_t *seed, size_t seed_len,
                     uint8_t *out, size_t out_len)
{
    const hash_ops_t *engine;
    const char *label;
    size_t label_len;
    int result;

    /* Validate inputs */
    if (!cfg || !out || out_len == 0 || out_len > SEED_MAX_OUTPUT_LEN) {
        return -1;
    }
    if (seed_len > 0 && !seed) {
        return -1;
    }

    /* --------- TIER 3: Check UDBF Override --------- */
    if (seed_udbf_is_active()) {
        /* Use UDBF test vector instead of normal derivation */
        label = cfg->ctx_label ? cfg->ctx_label : "";
        return udbf_read(label, out, out_len);
    }

    /* --------- TIER 2: Normal Hash-Based Derivation --------- */

    /* Select hash engine (default: SHA-512) */
    if (cfg->engine != NULL) {
        engine = cfg->engine;
    } else {
        /* Default to SHA-512 */
        engine = hash_lookup_by_name("sha512");
        if (!engine) {
            return -1;  /* SHA-512 not registered */
        }
    }

    /* Extract label */
    label = cfg->ctx_label ? cfg->ctx_label : "";
    label_len = label ? strlen(label) : 0;

    /* Validate label length */
    if (label_len > SEED_MAX_LABEL_LEN) {
        return -1;
    }

    /* Perform CTR-mode expansion */
    result = ctr_mode_expand(engine, seed, seed_len, label, label_len, out, out_len);

    return result;
}
