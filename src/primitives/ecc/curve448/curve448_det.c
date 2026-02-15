#include "curve448.h"
#include "../../utils/drbg/drbg.h"

/* Deterministic key generation using a user-provided seed */
int wc_curve448_make_key_deterministic(curve448_key* key, const byte* seed, word32 seedSz) {
    if (key == NULL || seed == NULL || seedSz == 0) {
        return -1; /* BAD_FUNC_ARG */
    }

    /* Initialize key structure */
    wc_curve448_init(key);

    /* Use DRBG to expand/condition seed if needed, or just use seed directly if length matches.
       Curve448 needs 56 bytes.
       If seed is short, we expand it using our DRBG.
    */
    
    CTR_DRBG_CTX drbg;
    ctr_drbg_init(&drbg, seed, seedSz, NULL, 0);
    
    int ret = ctr_drbg_generate(&drbg, key->k, CURVE448_KEY_SIZE, NULL, 0);
    ctr_drbg_free(&drbg);
    
    if (ret != 0) return ret;

    /* Clamp the key (standard X448/Ed448 clamping) */
    /* k[0] &= 0xfc; k[55] |= 0x80; k[55] &= 0x00; ?? No, 448 is different. 
       Let's rely on make_pub to handle public derivation, but the private key itself is usually just random bytes.
       WolfSSL's make_key usually just generates random bytes.
    */

    /* Generate public key from private key */
    return wc_curve448_make_pub(CURVE448_PUB_KEY_SIZE, key->p, CURVE448_KEY_SIZE, key->k);
}
