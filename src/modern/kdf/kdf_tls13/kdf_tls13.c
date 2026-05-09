/* kdf_tls13.c — TLS 1.3 Key Schedule (RFC 8446 §7.1) */
#include "kdf_tls13.h"
#include "../hkdf/hkdf.h"
#include "../hkdf_expand_label/hkdf_expand_label.h"
#include <string.h>

static const uint8_t ZEROS[48] = {0};

/* Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Hash(Messages), Nh) */
static int derive_secret(const uint8_t *secret, size_t secret_len,
                          const char *label, size_t label_len,
                          const uint8_t *msg_hash, size_t hash_len,
                          uint8_t *out, size_t out_len)
{
    return hkdf_expand_label(secret, secret_len,
                              label, label_len,
                              msg_hash, hash_len,
                              out, out_len);
}

int tls13_key_schedule(
        const uint8_t *psk,
        const uint8_t *dhe_shared,
        const uint8_t  client_hello_hash[TLS13_SECRET_LEN],
        const uint8_t  server_hello_hash[TLS13_SECRET_LEN],
        const uint8_t  handshake_hash[TLS13_SECRET_LEN],
        uint8_t        client_hs_traffic[TLS13_SECRET_LEN],
        uint8_t        server_hs_traffic[TLS13_SECRET_LEN],
        uint8_t        client_app_traffic[TLS13_SECRET_LEN],
        uint8_t        server_app_traffic[TLS13_SECRET_LEN],
        uint8_t        exporter_master[TLS13_SECRET_LEN],
        uint8_t        resumption_master[TLS13_SECRET_LEN])
{
    const uint8_t *psk_input = psk ? psk : ZEROS;
    const uint8_t *dhe_input = dhe_shared ? dhe_shared : ZEROS;

    /* Early Secret = HKDF-Extract(0, PSK) */
    uint8_t early_secret[TLS13_SECRET_LEN];
    if (hkdf_extract_ex(NULL, ZEROS, TLS13_SECRET_LEN,
                         psk_input, TLS13_SECRET_LEN,
                         early_secret) != 0) return -1;

    /* derived_early = Derive-Secret(early_secret, "derived", "") */
    uint8_t derived_early[TLS13_SECRET_LEN];
    /* Empty hash = SHA-256("") */
    static const uint8_t sha256_empty[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    if (derive_secret(early_secret, TLS13_SECRET_LEN,
                       "derived", 7, sha256_empty, 32,
                       derived_early, TLS13_SECRET_LEN) != 0) return -1;

    /* Handshake Secret = HKDF-Extract(derived_early, DHE) */
    uint8_t hs_secret[TLS13_SECRET_LEN];
    if (hkdf_extract_ex(NULL, derived_early, TLS13_SECRET_LEN,
                         dhe_input, TLS13_SECRET_LEN,
                         hs_secret) != 0) return -1;

    /* client/server handshake traffic secrets */
    if (derive_secret(hs_secret, TLS13_SECRET_LEN,
                       "c hs traffic", 12, server_hello_hash, TLS13_SECRET_LEN,
                       client_hs_traffic, TLS13_SECRET_LEN) != 0) return -1;
    if (derive_secret(hs_secret, TLS13_SECRET_LEN,
                       "s hs traffic", 12, server_hello_hash, TLS13_SECRET_LEN,
                       server_hs_traffic, TLS13_SECRET_LEN) != 0) return -1;

    /* derived_hs = Derive-Secret(hs_secret, "derived", "") */
    uint8_t derived_hs[TLS13_SECRET_LEN];
    if (derive_secret(hs_secret, TLS13_SECRET_LEN,
                       "derived", 7, sha256_empty, 32,
                       derived_hs, TLS13_SECRET_LEN) != 0) return -1;

    /* Master Secret = HKDF-Extract(derived_hs, 0) */
    uint8_t master_secret[TLS13_SECRET_LEN];
    if (hkdf_extract_ex(NULL, derived_hs, TLS13_SECRET_LEN,
                         ZEROS, TLS13_SECRET_LEN,
                         master_secret) != 0) return -1;

    /* Application traffic secrets */
    if (derive_secret(master_secret, TLS13_SECRET_LEN,
                       "c ap traffic", 12, handshake_hash, TLS13_SECRET_LEN,
                       client_app_traffic, TLS13_SECRET_LEN) != 0) return -1;
    if (derive_secret(master_secret, TLS13_SECRET_LEN,
                       "s ap traffic", 12, handshake_hash, TLS13_SECRET_LEN,
                       server_app_traffic, TLS13_SECRET_LEN) != 0) return -1;
    if (derive_secret(master_secret, TLS13_SECRET_LEN,
                       "exp master", 10, handshake_hash, TLS13_SECRET_LEN,
                       exporter_master, TLS13_SECRET_LEN) != 0) return -1;
    if (derive_secret(master_secret, TLS13_SECRET_LEN,
                       "res master", 10, handshake_hash, TLS13_SECRET_LEN,
                       resumption_master, TLS13_SECRET_LEN) != 0) return -1;

    memset(early_secret, 0, sizeof(early_secret));
    memset(hs_secret, 0, sizeof(hs_secret));
    memset(master_secret, 0, sizeof(master_secret));
    (void)client_hello_hash;
    return 0;
}

int tls13_derive_traffic_keys(
        const uint8_t  traffic_secret[TLS13_SECRET_LEN],
        uint8_t       *key,  size_t key_len,
        uint8_t        iv[12])
{
    if (!traffic_secret || !key || !iv) return -1;
    if (hkdf_expand_label(traffic_secret, TLS13_SECRET_LEN,
                           "key", 3, NULL, 0, key, key_len) != 0) return -1;
    if (hkdf_expand_label(traffic_secret, TLS13_SECRET_LEN,
                           "iv", 2, NULL, 0, iv, 12) != 0) return -1;
    return 0;
}
