#ifndef nextssl_LEGACY_UNSAFE_H
#define nextssl_LEGACY_UNSAFE_H

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

// --- Legacy (Unsafe) ---
// These algorithms are considered cryptographically broken.
// Included only for backward compatibility with ancient systems.

EXPORT int nextssl_md2(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_md4(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_sha0(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_ripemd128(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_ripemd256(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_ripemd320(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int nextssl_has160(const uint8_t *msg, size_t len, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // nextssl_LEGACY_UNSAFE_H
