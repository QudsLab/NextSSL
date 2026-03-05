/**
 * @file root/core/root_mac.h
 * @brief NextSSL Root â€” Explicit MAC algorithm interface.
 *
 * Naming: nextssl_root_mac_<algorithm>(...)
 */

#ifndef NEXTSSL_ROOT_MAC_H
#define NEXTSSL_ROOT_MAC_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * AES-CMAC  (NIST SP 800-38B / RFC 4493)
 * key[32] = AES-256 key.  mac[16] = 16-byte output.
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_mac_cmac(const uint8_t key[32],
                                       const uint8_t *data, size_t data_len,
                                       uint8_t mac[16]);

/* ------------------------------------------------------------------
 * SipHash-2-4
 * key[16] = 128-bit SipHash key.
 * out_len must be 8 (SipHash-2-4-64) or 16 (SipHash-2-4-128).
 * ------------------------------------------------------------------ */
NEXTSSL_API int nextssl_root_mac_siphash(const uint8_t key[16],
                                          const uint8_t *data, size_t data_len,
                                          uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ROOT_MAC_H */
