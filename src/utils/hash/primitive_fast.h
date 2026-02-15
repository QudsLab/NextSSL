#ifndef LEYLINE_PRIMITIVE_FAST_H
#define LEYLINE_PRIMITIVE_FAST_H

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

// --- Primitive (Fast) ---
EXPORT int leyline_sha224(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int leyline_sha256(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int leyline_sha384(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int leyline_sha512(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int leyline_blake3(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int leyline_blake2b(const uint8_t *msg, size_t len, uint8_t *out, size_t out_len);
EXPORT int leyline_blake2s(const uint8_t *msg, size_t len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif // LEYLINE_PRIMITIVE_FAST_H
