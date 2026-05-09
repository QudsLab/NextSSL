/* hpke.h — Hybrid Public Key Encryption (RFC 9180)
 *
 * HPKE is a standards-track hybrid PKE scheme combining a KEM with
 * a KDF and AEAD.  This API targets the following ciphersuites:
 *
 *   HPKE_SUITE_X25519_HKDF_SHA256_AES128GCM   (most common)
 *   HPKE_SUITE_X25519_HKDF_SHA256_CHACHA20POLY1305
 *   HPKE_SUITE_P256_HKDF_SHA256_AES128GCM
 *
 * Modes: Base, PSK, Auth, AuthPSK  (RFC 9180 §5)
 *
 * Reference: RFC 9180, examples/c/hpke/
 * NOTE: Full LabeledExtract / LabeledExpand per RFC 9180 §4 can be wired
 *       to replace the current direct HKDF calls.
 */
#ifndef NEXTSSL_HPKE_H
#define NEXTSSL_HPKE_H

#include <stdint.h>
#include <stddef.h>

/* KEM algorithm identifiers (RFC 9180 §7.1) */
typedef enum {
    HPKE_KEM_X25519_HKDF_SHA256  = 0x0020,
    HPKE_KEM_P256_HKDF_SHA256    = 0x0010
} hpke_kem_id_t;

/* KDF algorithm identifiers (RFC 9180 §7.2) */
typedef enum {
    HPKE_KDF_HKDF_SHA256 = 0x0001,
    HPKE_KDF_HKDF_SHA512 = 0x0003
} hpke_kdf_id_t;

/* AEAD algorithm identifiers (RFC 9180 §7.3) */
typedef enum {
    HPKE_AEAD_AES128GCM         = 0x0001,
    HPKE_AEAD_AES256GCM         = 0x0002,
    HPKE_AEAD_CHACHA20POLY1305  = 0x0003
} hpke_aead_id_t;

/* HPKE mode */
typedef enum {
    HPKE_MODE_BASE    = 0,
    HPKE_MODE_PSK     = 1,
    HPKE_MODE_AUTH    = 2,
    HPKE_MODE_AUTH_PSK = 3
} hpke_mode_t;

/* HPKE ciphersuite descriptor */
typedef struct {
    hpke_kem_id_t  kem_id;
    hpke_kdf_id_t  kdf_id;
    hpke_aead_id_t aead_id;
} hpke_suite_t;

/* Convenience suite constants */
#define HPKE_SUITE_X25519_HKDF_SHA256_AES128GCM \
    ((hpke_suite_t){ HPKE_KEM_X25519_HKDF_SHA256, HPKE_KDF_HKDF_SHA256, HPKE_AEAD_AES128GCM })
#define HPKE_SUITE_P256_HKDF_SHA256_AES128GCM \
    ((hpke_suite_t){ HPKE_KEM_P256_HKDF_SHA256, HPKE_KDF_HKDF_SHA256, HPKE_AEAD_AES128GCM })

/* Opaque HPKE sender / recipient context */
typedef struct hpke_sender_ctx   hpke_sender_ctx_t;
typedef struct hpke_recipient_ctx hpke_recipient_ctx_t;

/* --- Sender API --- */

/* hpke_sender_setup — encapsulate a key and set up a sender context.
 *
 * suite         : ciphersuite to use
 * mode          : HPKE_MODE_BASE or HPKE_MODE_PSK
 * recipient_pub : recipient's public key (32 bytes for X25519, 64 for P-256)
 * info          : application-defined context string
 * info_len      : length of info
 * psk / psk_id  : PSK and PSK ID (only for PSK modes; NULL otherwise)
 * enc_buf       : output encapsulated key (caller-allocated, 32 or 65 bytes)
 * enc_len       : in/out: capacity / actual enc bytes written
 * Returns a newly allocated sender context, or NULL on error. */
hpke_sender_ctx_t *hpke_sender_setup(
        hpke_suite_t    suite,
        hpke_mode_t     mode,
        const uint8_t  *recipient_pub, size_t pub_len,
        const uint8_t  *info,          size_t info_len,
        const uint8_t  *psk,           size_t psk_len,
        const uint8_t  *psk_id,        size_t psk_id_len,
        uint8_t        *enc_buf,       size_t *enc_len);

/* hpke_seal — single-shot encryption.
 * aad / pt / ct: standard AEAD interface; ct must be pt_len + tag_size larger. */
int hpke_seal(hpke_sender_ctx_t *ctx,
              const uint8_t *aad,   size_t aad_len,
              const uint8_t *pt,    size_t pt_len,
              uint8_t       *ct,    size_t *ct_len);

void hpke_sender_ctx_free(hpke_sender_ctx_t *ctx);

/* --- Recipient API --- */

/* hpke_recipient_setup — decapsulate and set up a recipient context.
 *
 * enc_buf       : encapsulated key from sender
 * recipient_priv: recipient's private key
 * Returns a newly allocated recipient context, or NULL on error. */
hpke_recipient_ctx_t *hpke_recipient_setup(
        hpke_suite_t    suite,
        hpke_mode_t     mode,
        const uint8_t  *enc_buf,        size_t enc_len,
        const uint8_t  *recipient_priv, size_t priv_len,
        const uint8_t  *info,           size_t info_len,
        const uint8_t  *psk,            size_t psk_len,
        const uint8_t  *psk_id,         size_t psk_id_len);

int hpke_open(hpke_recipient_ctx_t *ctx,
              const uint8_t *aad,  size_t aad_len,
              const uint8_t *ct,   size_t ct_len,
              uint8_t       *pt,   size_t *pt_len);

void hpke_recipient_ctx_free(hpke_recipient_ctx_t *ctx);

#endif /* NEXTSSL_HPKE_H */
