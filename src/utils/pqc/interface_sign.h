#ifndef LEYLINE_INTERFACE_SIGN_H
#define LEYLINE_INTERFACE_SIGN_H

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

// --- ML-DSA (Dilithium) ---
EXPORT int leyline_dilithium2_keypair(uint8_t *pk, uint8_t *sk);
EXPORT int leyline_dilithium3_keypair(uint8_t *pk, uint8_t *sk);
EXPORT int leyline_dilithium5_keypair(uint8_t *pk, uint8_t *sk);

EXPORT int leyline_dilithium2_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
EXPORT int leyline_dilithium3_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
EXPORT int leyline_dilithium5_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);

EXPORT int leyline_dilithium2_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);
EXPORT int leyline_dilithium3_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);
EXPORT int leyline_dilithium5_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

// --- SPHINCS+ ---
// (Simplified Interface for now)
EXPORT int leyline_sphincs_shake_128f_simple_keypair(uint8_t *pk, uint8_t *sk);
EXPORT int leyline_sphincs_shake_128f_simple_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
EXPORT int leyline_sphincs_shake_128f_simple_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

#ifdef __cplusplus
}
#endif

#endif // LEYLINE_INTERFACE_SIGN_H
