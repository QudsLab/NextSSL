/* slip10.c — SLIP-0010 HD Key Derivation */
#include "slip10.h"
#include "../../mac/hmac/hmac.h"
#include <string.h>

/* HMAC-SHA512 key for each curve */
static const char *slip10_hmac_key(slip10_curve_t curve)
{
    switch (curve) {
        case SLIP10_CURVE_SECP256K1: return "Bitcoin seed";
        case SLIP10_CURVE_NIST_P256: return "Nist256p1 seed";
        case SLIP10_CURVE_ED25519:   return "ed25519 seed";
    }
    return NULL;
}

int slip10_master_key(slip10_curve_t curve,
                       const uint8_t *seed, size_t seed_len,
                       uint8_t key_out[SLIP10_KEY_SIZE],
                       uint8_t chain_out[SLIP10_CHAINCODE_SIZE])
{
    if (!seed || !key_out || !chain_out) return -1;
    if (seed_len < 16 || seed_len > 64) return -1;

    const char *hmac_key = slip10_hmac_key(curve);
    if (!hmac_key) return -1;

    uint8_t I[64];
    if (hmac_compute(HMAC_SHA512,
                      (const uint8_t *)hmac_key, strlen(hmac_key),
                      seed, seed_len,
                      I, NULL) != 0) return -1;

    memcpy(key_out,   I,      32);
    memcpy(chain_out, I + 32, 32);
    memset(I, 0, sizeof(I));
    return 0;
}

int slip10_child_key(slip10_curve_t curve,
                      const uint8_t parent_key[SLIP10_KEY_SIZE],
                      const uint8_t parent_chain[SLIP10_CHAINCODE_SIZE],
                      uint32_t      index,
                      uint8_t       child_key[SLIP10_KEY_SIZE],
                      uint8_t       child_chain[SLIP10_CHAINCODE_SIZE])
{
    if (!parent_key || !parent_chain || !child_key || !child_chain) return -1;

    /* ed25519 only supports hardened derivation */
    if (curve == SLIP10_CURVE_ED25519 && index < 0x80000000u) return -1;

    uint8_t data[37];
    size_t  data_len = 0;

    if (index >= 0x80000000u) {
        /* Hardened: 0x00 || key || index */
        data[0] = 0x00;
        memcpy(data + 1, parent_key, 32);
        data_len = 33;
    } else {
        /* Normal (secp256k1/P-256): serP(public) || index
         * NOTE: Full SLIP-10 requires a compressed public key from the EC backend.
         * Replace with the proper pubkey_compress() call when wired. */
        data[0] = 0x02;
        memcpy(data + 1, parent_key, 32);
        data_len = 33;
    }
    data[data_len++] = (uint8_t)(index >> 24);
    data[data_len++] = (uint8_t)(index >> 16);
    data[data_len++] = (uint8_t)(index >>  8);
    data[data_len++] = (uint8_t)(index);

    uint8_t I[64];
    if (hmac_compute(HMAC_SHA512, parent_chain, 32, data, data_len, I, NULL) != 0) return -1;

    /* child_key = IL (for ed25519: direct; for ECDSA: IL + parent mod n)
     * NOTE: ECDSA curves require mod-n addition; ed25519 uses IL directly. */
    memcpy(child_key,   I,      32);
    memcpy(child_chain, I + 32, 32);
    memset(I, 0, sizeof(I));
    return 0;
}
