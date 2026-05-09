/* slip10.h — SLIP-0010 Universal HD Key Derivation (Bitcoin/Ethereum extended)
 *
 * SLIP-0010 extends BIP-32 key derivation to other curves:
 *   - secp256k1  (Bitcoin, HMAC key = "Bitcoin seed")
 *   - NIST P-256 (HMAC key = "Nist256p1 seed")
 *   - ed25519    (HMAC key = "ed25519 seed")  — only hardened derivation
 *
 * Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
 * Dependency: bip32_kdf (for secp256k1 path), ed25519 backend
 */
#ifndef NEXTSSL_SLIP10_H
#define NEXTSSL_SLIP10_H

#include <stdint.h>
#include <stddef.h>

#define SLIP10_KEY_SIZE      32u
#define SLIP10_CHAINCODE_SIZE 32u

typedef enum {
    SLIP10_CURVE_SECP256K1 = 0,
    SLIP10_CURVE_NIST_P256 = 1,
    SLIP10_CURVE_ED25519   = 2
} slip10_curve_t;

/* slip10_master_key — Derive SLIP-0010 master key for the given curve.
 * seed: 16..64 bytes of seed material.
 * Returns 0 on success. */
int slip10_master_key(slip10_curve_t  curve,
                       const uint8_t  *seed,      size_t seed_len,
                       uint8_t         key_out[SLIP10_KEY_SIZE],
                       uint8_t         chain_out[SLIP10_CHAINCODE_SIZE]);

/* slip10_child_key — Derive a child key.
 * index: use BIP32_HARDENED_OFFSET (0x80000000) for hardened.
 * Note: ed25519 only supports hardened derivation. */
int slip10_child_key(slip10_curve_t  curve,
                      const uint8_t  parent_key[SLIP10_KEY_SIZE],
                      const uint8_t  parent_chain[SLIP10_CHAINCODE_SIZE],
                      uint32_t       index,
                      uint8_t        child_key[SLIP10_KEY_SIZE],
                      uint8_t        child_chain[SLIP10_CHAINCODE_SIZE]);

#endif /* NEXTSSL_SLIP10_H */
