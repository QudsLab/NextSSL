/* bip32_kdf.c — BIP-32 HD Key Derivation */
#include "bip32_kdf.h"
#include "../../../hash/sha512/sha512.h"
#include "../../mac/hmac/hmac.h"
#include <string.h>

int bip32_master_key(const uint8_t *seed, size_t seed_len,
                      uint8_t key_out[BIP32_KEY_SIZE],
                      uint8_t chain_out[BIP32_CHAINCODE_SIZE])
{
    if (!seed || !key_out || !chain_out) return -1;
    if (seed_len < BIP32_SEED_MIN_SIZE || seed_len > BIP32_SEED_MAX_SIZE) return -1;

    /* I = HMAC-SHA512(Key="Bitcoin seed", Data=seed) */
    static const uint8_t hmac_key[] = "Bitcoin seed";
    uint8_t I[64];
    if (hmac_compute(HMAC_SHA512,
                      hmac_key, sizeof(hmac_key) - 1,
                      seed, seed_len,
                      I, NULL) != 0) return -1;

    /* IL = first 32 bytes = master private key */
    /* IR = last 32 bytes  = master chain code */
    memcpy(key_out,   I,      32);
    memcpy(chain_out, I + 32, 32);
    memset(I, 0, sizeof(I));
    return 0;
}

int bip32_child_key_private(const uint8_t parent_key[BIP32_KEY_SIZE],
                              const uint8_t parent_chain[BIP32_CHAINCODE_SIZE],
                              uint32_t      index,
                              uint8_t       child_key[BIP32_KEY_SIZE],
                              uint8_t       child_chain[BIP32_CHAINCODE_SIZE])
{
    if (!parent_key || !parent_chain || !child_key || !child_chain) return -1;

    uint8_t data[37]; /* 33 bytes (key or point) + 4 bytes (index) */
    size_t  data_len;

    if (index >= BIP32_HARDENED_OFFSET) {
        /* Hardened: data = 0x00 || parent_key || ser32(index) */
        data[0] = 0x00;
        memcpy(data + 1, parent_key, 32);
        data_len = 33;
    } else {
        /* Normal: data = serP(parent_public_key) || ser32(index)
         * TODO: Requires compressed public key from secp256k1.
         * For now, use the private key with 0x02 prefix as placeholder.
         * Replace with proper secp256k1_pubkey_compress() call. */
        data[0] = 0x02;
        memcpy(data + 1, parent_key, 32);
        data_len = 33;
    }

    /* Append 4-byte big-endian index */
    data[data_len++] = (uint8_t)(index >> 24);
    data[data_len++] = (uint8_t)(index >> 16);
    data[data_len++] = (uint8_t)(index >>  8);
    data[data_len++] = (uint8_t)(index);

    /* I = HMAC-SHA512(parent_chain, data) */
    uint8_t I[64];
    if (hmac_compute(HMAC_SHA512, parent_chain, 32, data, data_len, I, NULL) != 0) return -1;

    /* child_key = (IL + parent_key) mod n
     * Simplified: store IL directly (full mod-n addition requires secp256k1 bignum).
     * TODO: Replace with secp256k1_scalar_add(child_key, I[0:32], parent_key) */
    for (int i = 0; i < 32; i++)
        child_key[i] = I[i] ^ parent_key[i];  /* placeholder XOR until proper mod-n */

    memcpy(child_chain, I + 32, 32);
    memset(I, 0, sizeof(I));
    return 0;
}
