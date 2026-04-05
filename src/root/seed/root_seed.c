/* root_seed.c — Seed API Implementation (Plan 405)
 *
 * Thin export layer over src/seed/.
 */
#include "root_seed.h"
#include "../../seed/random/seed_derive_random.h"
#include "../../seed/hash/seed_core.h"
#include "../../seed/hash/hash_registry.h"
#include "../../seed/udbf/udbf.h"
#include <string.h>

/* -------------------------------------------------------------------------
 * nextssl_seed_random
 * -------------------------------------------------------------------------*/
int nextssl_seed_random(uint8_t *out, size_t len)
{
    return seed_derive_random(out, len);
}

/* -------------------------------------------------------------------------
 * nextssl_seed_derive
 * -------------------------------------------------------------------------*/
int nextssl_seed_derive(
    const char    *algo,
    const char    *label,
    const uint8_t *seed,
    size_t         seed_len,
    uint8_t       *out,
    size_t         out_len)
{
    seed_hash_config_t cfg;

    cfg.ctx_label = label;  /* NULL is accepted by seed_hash_derive */

    if (algo && algo[0] != '\0') {
        cfg.engine = hash_lookup_by_name(algo);
        if (!cfg.engine) {
            return -1;  /* Unrecognised algorithm name */
        }
    } else {
        cfg.engine = NULL;  /* Default: SHA-512 */
    }

    return seed_hash_derive(&cfg, seed, seed_len, out, out_len);
}

/* -------------------------------------------------------------------------
 * nextssl_seed_udbf_feed
 * -------------------------------------------------------------------------*/
int nextssl_seed_udbf_feed(const uint8_t *data, size_t len)
{
    return udbf_feed(data, len);
}

/* -------------------------------------------------------------------------
 * nextssl_seed_udbf_wipe
 * -------------------------------------------------------------------------*/
void nextssl_seed_udbf_wipe(void)
{
    udbf_wipe();
}
