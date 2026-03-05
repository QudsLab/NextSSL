/**
 * @file root/core/root_mac.c
 * @brief NextSSL Root — MAC implementation.
 */

#include "root_mac.h"
#include "../root_internal.h"

/* Need aes_internal.h for block_t before including aes_cmac.h */
#include "../../../../../primitives/cipher/aes_core/aes_internal.h"
#include "../../../../../primitives/mac/aes_cmac/aes_cmac.h"
#include "../../../../../primitives/mac/siphash/siphash.h"

/* =========================================================================
 * AES-CMAC  (NIST SP 800-38B)
 * ====================================================================== */

NEXTSSL_API int nextssl_root_mac_cmac(const uint8_t key[32],
                                       const uint8_t *data, size_t data_len,
                                       uint8_t mac[16]) {
    if (!key || !mac) return -1;
    if (data_len > 0 && !data) return -1;
    /* AES_CMAC(key, data, dataSize, block_t mac_out) */
    AES_CMAC(key, (void *)data, data_len, mac);
    return 0;
}

/* =========================================================================
 * SipHash-2-4
 * ====================================================================== */

NEXTSSL_API int nextssl_root_mac_siphash(const uint8_t key[16],
                                          const uint8_t *data, size_t data_len,
                                          uint8_t *out, size_t out_len) {
    if (!key || !out) return -1;
    if (out_len != 8 && out_len != 16) return -1;
    if (data_len > 0 && !data) return -1;
    return siphash((void *)data, data_len, key, out, out_len);
}
