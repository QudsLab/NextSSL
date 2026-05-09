/* kdf_tls13.h — TLS 1.3 Key Schedule (RFC 8446 §7.1)
 *
 * TLS 1.3 derives all session keys from a hierarchical HKDF key schedule:
 *
 *   Early Secret  = HKDF-Extract(0, PSK or 0)
 *   Handshake Secret = HKDF-Extract(Derive-Secret(ES, "derived"), DHE)
 *   Master Secret = HKDF-Extract(Derive-Secret(HS, "derived"), 0)
 *
 * From each stage, traffic keys are derived via Derive-Secret / Expand-Label.
 *
 * Reference: RFC 8446 §7.1
 * Dependency: hkdf_expand_label
 */
#ifndef NEXTSSL_KDF_TLS13_H
#define NEXTSSL_KDF_TLS13_H

#include <stdint.h>
#include <stddef.h>

#define TLS13_SECRET_LEN  32u  /* SHA-256 hash length; SHA-384 = 48 */

/* tls13_key_schedule — full TLS 1.3 key schedule (SHA-256 variant).
 *
 * psk           : pre-shared key (32 bytes), or NULL/zeros for no PSK
 * dhe_shared    : Diffie-Hellman shared secret (32 bytes), or NULL
 * client_hello_hash    : SHA-256 hash of ClientHello message (32 bytes)
 * server_hello_hash    : SHA-256 hash of ClientHello..ServerHello (32 bytes)
 * handshake_hash       : SHA-256 hash of ClientHello..ServerFinished (32 bytes)
 *
 * Outputs (all 32 bytes each):
 *   client_handshake_traffic_secret
 *   server_handshake_traffic_secret
 *   client_app_traffic_secret
 *   server_app_traffic_secret
 *   exporter_master_secret
 *   resumption_master_secret
 *
 * Returns 0 on success, -1 on error. */
int tls13_key_schedule(
        const uint8_t *psk,                      /* [32] or NULL */
        const uint8_t *dhe_shared,               /* [32] or NULL */
        const uint8_t  client_hello_hash[TLS13_SECRET_LEN],
        const uint8_t  server_hello_hash[TLS13_SECRET_LEN],
        const uint8_t  handshake_hash[TLS13_SECRET_LEN],
        uint8_t        client_hs_traffic[TLS13_SECRET_LEN],
        uint8_t        server_hs_traffic[TLS13_SECRET_LEN],
        uint8_t        client_app_traffic[TLS13_SECRET_LEN],
        uint8_t        server_app_traffic[TLS13_SECRET_LEN],
        uint8_t        exporter_master[TLS13_SECRET_LEN],
        uint8_t        resumption_master[TLS13_SECRET_LEN]);

/* tls13_derive_traffic_keys — derive AEAD key + IV from a traffic secret.
 *
 * traffic_secret: 32-byte input (from tls13_key_schedule outputs)
 * key           : output key (key_len bytes)
 * key_len       : desired key length (16 or 32 for AES-128/256-GCM)
 * iv            : output IV (12 bytes for AES-GCM)
 * Returns 0 on success. */
int tls13_derive_traffic_keys(
        const uint8_t  traffic_secret[TLS13_SECRET_LEN],
        uint8_t       *key,  size_t key_len,
        uint8_t        iv[12]);

#endif /* NEXTSSL_KDF_TLS13_H */
