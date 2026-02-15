#ifndef LEYLINE_INTERFACE_KEM_H
#define LEYLINE_INTERFACE_KEM_H

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

// --- ML-KEM (Kyber) ---
// Keygen
EXPORT int leyline_kyber512_keypair(uint8_t *pk, uint8_t *sk);
EXPORT int leyline_kyber768_keypair(uint8_t *pk, uint8_t *sk);
EXPORT int leyline_kyber1024_keypair(uint8_t *pk, uint8_t *sk);

// Encapsulate
EXPORT int leyline_kyber512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
EXPORT int leyline_kyber768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
EXPORT int leyline_kyber1024_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

// Decapsulate
EXPORT int leyline_kyber512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
EXPORT int leyline_kyber768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
EXPORT int leyline_kyber1024_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif // LEYLINE_INTERFACE_KEM_H
