#ifndef HKDF_H
#define HKDF_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
  #define PQC_API __declspec(dllexport)
#else
  #define PQC_API __attribute__((visibility("default")))
#endif

/* HKDF-SHA256 */
PQC_API int hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk);
PQC_API int hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);
PQC_API int hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

/* HKDF-SHA3-256 */
PQC_API int hkdf_sha3_256_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk);
PQC_API int hkdf_sha3_256_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);
PQC_API int hkdf_sha3_256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

/* HKDF-SHA3-512 */
PQC_API int hkdf_sha3_512_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk);
PQC_API int hkdf_sha3_512_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);
PQC_API int hkdf_sha3_512(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

/* HKDF-Expand-Label (RFC 8446) - Uses SHA256 by default */
PQC_API int hkdf_expand_label(const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *context, size_t context_len, uint8_t *okm, size_t okm_len);

/* XOF-based KDF (SHAKE256) */
PQC_API void kdf_shake256(const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

/* Exposed HMAC functions */
PQC_API void pqc_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out);
PQC_API void hmac_sha3_256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out);
PQC_API void hmac_sha3_512(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out);

#endif
