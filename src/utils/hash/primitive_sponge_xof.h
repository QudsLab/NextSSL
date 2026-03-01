#ifndef nextssl_PRIMITIVE_SPONGE_XOF_H
#define nextssl_PRIMITIVE_SPONGE_XOF_H

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Primitive (Sponge/XOF) ---
EXPORT int nextssl_sha3_224(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_sha3_256(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_sha3_384(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_sha3_512(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_keccak_256(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_shake128(const uint8_t *msg, size_t len, uint8_t *out, size_t out_len);
EXPORT int nextssl_shake256(const uint8_t *msg, size_t len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif // nextssl_PRIMITIVE_SPONGE_XOF_H
