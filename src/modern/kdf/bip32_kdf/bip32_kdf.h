/* bip32_kdf.h — BIP-32 Hierarchical Deterministic Key Derivation
 *
 * BIP-32 derives child keys from a parent key + chaincode using HMAC-SHA512:
 *   If hardened: I = HMAC-SHA512(Key=chaincode, Data=0x00||k||ser32(i))
 *   If normal:   I = HMAC-SHA512(Key=chaincode, Data=serP(K)||ser32(i))
 *   IL = I[0:32]  → child key (or addition mod n for normal derivation)
 *   IR = I[32:64] → child chaincode
 *
 * The master key is derived from a seed:
 *   I = HMAC-SHA512(Key="Bitcoin seed", Data=seed)
 *
 * Reference: BIP-32 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
 * Dependency: secp256k1 backend (for normal child derivation point addition)
 */
#ifndef NEXTSSL_BIP32_KDF_H
#define NEXTSSL_BIP32_KDF_H

#include <stdint.h>
#include <stddef.h>

#define BIP32_KEY_SIZE      32u
#define BIP32_CHAINCODE_SIZE 32u
#define BIP32_SEED_MIN_SIZE 16u
#define BIP32_SEED_MAX_SIZE 64u

/* Hardened key index range: 0x80000000 and above */
#define BIP32_HARDENED_OFFSET 0x80000000u

/* bip32_master_key — Derive BIP-32 master key from seed.
 * seed      : random seed bytes (16..64 bytes)
 * seed_len  : seed length
 * key_out   : 32-byte output private key
 * chain_out : 32-byte output chain code
 * Returns 0 on success. */
int bip32_master_key(const uint8_t *seed, size_t seed_len,
                      uint8_t key_out[BIP32_KEY_SIZE],
                      uint8_t chain_out[BIP32_CHAINCODE_SIZE]);

/* bip32_child_key_private — Derive child private key.
 * parent_key   : 32-byte parent private key
 * parent_chain : 32-byte parent chain code
 * index        : child index (add BIP32_HARDENED_OFFSET for hardened)
 * child_key    : 32-byte output child private key
 * child_chain  : 32-byte output child chain code
 * Returns 0 on success. */
int bip32_child_key_private(const uint8_t parent_key[BIP32_KEY_SIZE],
                              const uint8_t parent_chain[BIP32_CHAINCODE_SIZE],
                              uint32_t      index,
                              uint8_t       child_key[BIP32_KEY_SIZE],
                              uint8_t       child_chain[BIP32_CHAINCODE_SIZE]);

#endif /* NEXTSSL_BIP32_KDF_H */
