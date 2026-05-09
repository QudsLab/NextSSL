/* kdf_ike.h — IKE Key Derivation (RFC 7296 §2.13 / RFC 5996)
 *
 * IKEv2 key derivation uses HMAC-SHA256 (or AES-XCBC-PRF-128) as the PRF
 * in a specific hierarchy:
 *
 *   SKEYSEED = prf(Ni | Nr, g^ir)
 *   {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} =
 *       prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
 *
 * prf+ expands using:
 *   T1 = prf(K, S | 0x01)
 *   T2 = prf(K, T1 | S | 0x02)
 *   ...
 *
 * Reference: RFC 7296 §2.13, examples/c/ike/
 * Dependency: xcbc_mac (for AES-XCBC-PRF-128 variant)
 */
#ifndef NEXTSSL_KDF_IKE_H
#define NEXTSSL_KDF_IKE_H

#include <stdint.h>
#include <stddef.h>

#define IKE_SKEYSEED_SIZE  32u  /* HMAC-SHA256 output */
#define IKE_SPI_SIZE        8u  /* IKE SPI is 8 bytes */

/* ike_skeyseed — Compute IKEv2 SKEYSEED.
 * prf key = Ni | Nr; input = g^ir (DH shared secret)
 * Ni, Nr: nonces; g_ir: DH output; skeyseed: 32-byte output.
 * Returns 0 on success. */
int ike_skeyseed(const uint8_t *Ni,   size_t Ni_len,
                  const uint8_t *Nr,   size_t Nr_len,
                  const uint8_t *g_ir, size_t g_ir_len,
                  uint8_t        skeyseed[IKE_SKEYSEED_SIZE]);

/* ike_prf_plus — Expand IKEv2 key material via prf+.
 * K        : PRF key (skeyseed or SK_d)
 * K_len    : length of K
 * S        : seed data (Ni | Nr | SPIi | SPIr, etc.)
 * S_len    : length of S
 * out      : output key material
 * out_len  : total bytes desired
 * Returns 0 on success. */
int ike_prf_plus(const uint8_t *K,   size_t K_len,
                  const uint8_t *S,   size_t S_len,
                  uint8_t       *out, size_t out_len);

/* ike_key_material — Derive all IKEv2 child SA keys in one call.
 * skeyseed : 32 bytes from ike_skeyseed()
 * Ni, Nr   : nonces
 * SPIi, SPIr: 8-byte SPIs
 * key_mat  : caller-allocated output (at least key_mat_len bytes)
 * key_mat_len: total key material desired (e.g. 32+20+20+16+16+32+32) */
int ike_key_material(const uint8_t  skeyseed[IKE_SKEYSEED_SIZE],
                      const uint8_t *Ni,    size_t Ni_len,
                      const uint8_t *Nr,    size_t Nr_len,
                      const uint8_t  SPIi[IKE_SPI_SIZE],
                      const uint8_t  SPIr[IKE_SPI_SIZE],
                      uint8_t       *key_mat, size_t key_mat_len);

#endif /* NEXTSSL_KDF_IKE_H */
