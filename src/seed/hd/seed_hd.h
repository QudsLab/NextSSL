#ifndef NEXTSSL_SEED_HD_H
#define NEXTSSL_SEED_HD_H

#include <stddef.h>
#include <stdint.h>

/*
 * seed_hd.h — Hierarchical Deterministic key derivation (BIP32-inspired)
 *
 * Derives an entire key tree from a single master seed using
 * HMAC-SHA512 based child-key derivation.
 *
 * Path syntax: "m/44'/0'/0'/0/0"
 *   - Integer segments separated by '/'
 *   - Trailing ' marks a hardened derivation
 *   - Leading 'm' is optional (ignored)
 *   - Hardened index = segment + 0x80000000
 *
 * Hardened child: HMAC-SHA512(chain_code, 0x00 || parent_key || BE32(index))
 * Normal child:   HMAC-SHA512(chain_code, BE32(index)) — uses index directly
 *
 * Note: "Normal" derivation here means HMAC-SHA512(chain_code, key || BE32(i))
 * for a symmetric-only tree (no public key derivation is supported —
 * this is not a full BIP44 wallet).
 */

/*
 * seed_hd_master — derive master key and chain code from a seed.
 *
 * Uses: HMAC-SHA512("NextSSL seed", master_seed)
 * Output: master_key[32], chain_code[32] (left/right halves of 64-byte HMAC)
 *
 * seed_len must be between 16 and 64 bytes.
 * Returns 0 on success, -1 on invalid arguments.
 */
int seed_hd_master(const uint8_t *master_seed, size_t seed_len,
                   uint8_t        master_key[32],
                   uint8_t        chain_code[32]);

/*
 * seed_hd_derive — derive a child key+chain from parent key+chain at one level.
 *
 * path_segment: single integer (0x80000000 bit set = hardened)
 * Returns 0 on success, -1 on error.
 */
int seed_hd_child(const uint8_t *parent_key,   /* 32 bytes */
                  const uint8_t *chain_code,    /* 32 bytes */
                  uint32_t       index,          /* hardened if bit 31 set */
                  uint8_t        child_key[32],
                  uint8_t        child_chain[32]);

/*
 * seed_hd — convenience: master seed + full path → 32-byte output key.
 *
 * path examples: "m/44'/0'/0'", "0'/1/2", "m/0"
 * out must be 32 bytes.
 * Returns 0 on success, -1 on invalid path or derivation error.
 */
int seed_hd_derive(const uint8_t *master_seed, size_t seed_len,
                   const char    *path,
                   uint8_t       *out,          size_t out_len);

#endif /* NEXTSSL_SEED_HD_H */
