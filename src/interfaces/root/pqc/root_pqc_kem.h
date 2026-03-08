/**
 * @file root/pqc/root_pqc_kem.h
 * @brief NextSSL Root — Explicit post-quantum KEM interface.
 *
 * Naming: nextssl_root_pqc_kem_<algorithm>_{keygen|encaps|decaps}(...)
 *
 * Key/ciphertext sizes (bytes) — use these to size your buffers:
 *
 *   ML-KEM-512   pk=800    sk=1632   ct=768    ss=32
 *   ML-KEM-768   pk=1184   sk=2400   ct=1088   ss=32
 *   ML-KEM-1024  pk=1568   sk=3168   ct=1568   ss=32
 *
 *   HQC-128      pk=2249   sk=2305   ct=4433   ss=64
 *   HQC-192      pk=4522   sk=4586   ct=8978   ss=64
 *   HQC-256      pk=7245   sk=7317   ct=14469  ss=64
 *
 *   McEliece-348864     pk=261120  sk=6492   ct=96   ss=32
 *   McEliece-348864f    pk=261120  sk=6492   ct=96   ss=32
 *   McEliece-460896     pk=524160  sk=13608  ct=156  ss=32
 *   McEliece-460896f    pk=524160  sk=13608  ct=156  ss=32
 *   McEliece-6688128    pk=1044992 sk=13932  ct=240  ss=32
 *   McEliece-6688128f   pk=1044992 sk=13932  ct=240  ss=32
 *   McEliece-6960119    pk=1047319 sk=13948  ct=226  ss=32
 *   McEliece-6960119f   pk=1047319 sk=13948  ct=226  ss=32
 *   McEliece-8192128    pk=1357824 sk=14120  ct=240  ss=32
 *   McEliece-8192128f   pk=1357824 sk=14120  ct=240  ss=32
 *
 * Return: 0 success, -1 error.
 */

#ifndef NEXTSSL_ROOT_PQC_KEM_H
#define NEXTSSL_ROOT_PQC_KEM_H

#include <stddef.h>
#include <stdint.h>
#include "../../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * ML-KEM (Module Lattice-based KEM — NIST FIPS 203)
 * ============================================================== */

#ifndef NEXTSSL_BUILD_LITE
NEXTSSL_API int nextssl_root_pqc_kem_mlkem512_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mlkem512_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mlkem512_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mlkem768_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mlkem768_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mlkem768_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);
#endif /* NEXTSSL_BUILD_LITE */

NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

/* ================================================================
 * HQC (Hamming Quasi-Cyclic)
 * ss = 64 bytes for all HQC variants
 * ============================================================== */

#ifndef NEXTSSL_BUILD_LITE

NEXTSSL_API int nextssl_root_pqc_kem_hqc128_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_hqc128_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[64]);
NEXTSSL_API int nextssl_root_pqc_kem_hqc128_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[64]);

NEXTSSL_API int nextssl_root_pqc_kem_hqc192_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_hqc192_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[64]);
NEXTSSL_API int nextssl_root_pqc_kem_hqc192_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[64]);

NEXTSSL_API int nextssl_root_pqc_kem_hqc256_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_hqc256_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[64]);
NEXTSSL_API int nextssl_root_pqc_kem_hqc256_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[64]);

/* ================================================================
 * Classic McEliece
 * All variants: ss = 32 bytes.
 * Warning: Public keys are very large (see header comments above).
 * ============================================================== */

NEXTSSL_API int nextssl_root_pqc_kem_mceliece348864_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece348864_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece348864_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mceliece348864f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece348864f_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece348864f_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mceliece460896_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece460896_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece460896_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mceliece460896f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece460896f_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece460896f_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mceliece6688128_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece6688128_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece6688128_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mceliece6688128f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece6688128f_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece6688128f_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mceliece6960119_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece6960119_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece6960119_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mceliece6960119f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece6960119f_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece6960119f_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mceliece8192128_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece8192128_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece8192128_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

NEXTSSL_API int nextssl_root_pqc_kem_mceliece8192128f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece8192128f_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]);
NEXTSSL_API int nextssl_root_pqc_kem_mceliece8192128f_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]);

#endif /* NEXTSSL_BUILD_LITE */

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ROOT_PQC_KEM_H */
