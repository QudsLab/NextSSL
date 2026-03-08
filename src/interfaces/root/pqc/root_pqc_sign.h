/**
 * @file root/pqc/root_pqc_sign.h
 * @brief NextSSL Root — Explicit post-quantum signature interface.
 *
 * Naming: nextssl_root_pqc_sign_<algorithm>_{keygen|sign|verify}(...)
 *
 * Key/signature sizes (bytes):
 *
 *   ML-DSA-44     pk=1312   sk=2560   sig_max=2420
 *   ML-DSA-65     pk=1952   sk=4032   sig_max=3309
 *   ML-DSA-87     pk=2592   sk=4896   sig_max=4627
 *
 *   Falcon-512           pk=897    sk=1281   sig_max=752
 *   Falcon-1024          pk=1793   sk=2305   sig_max=1330
 *   Falcon-padded-512    pk=897    sk=1281   sig=666  (fixed)
 *   Falcon-padded-1024   pk=1793   sk=2305   sig=1280 (fixed)
 *
 *   SPHINCS+-sha2-128f   pk=32    sk=64    sig=17088
 *   SPHINCS+-sha2-128s   pk=32    sk=64    sig=7856
 *   SPHINCS+-sha2-192f   pk=48    sk=96    sig=35664
 *   SPHINCS+-sha2-192s   pk=48    sk=96    sig=16224
 *   SPHINCS+-sha2-256f   pk=64    sk=128   sig=49856
 *   SPHINCS+-sha2-256s   pk=64    sk=128   sig=29792
 *
 *   SPHINCS+-shake-128f  pk=32    sk=64    sig=17088
 *   SPHINCS+-shake-128s  pk=32    sk=64    sig=7856
 *   SPHINCS+-shake-192f  pk=48    sk=96    sig=35664
 *   SPHINCS+-shake-192s  pk=48    sk=96    sig=16224
 *   SPHINCS+-shake-256f  pk=64    sk=128   sig=49856
 *   SPHINCS+-shake-256s  pk=64    sk=128   sig=29792
 *
 * sign() sets *sig_len to the actual signature length written.
 * verify() returns 1 valid, 0 invalid, -1 error.
 */

#ifndef NEXTSSL_ROOT_PQC_SIGN_H
#define NEXTSSL_ROOT_PQC_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "../../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * ML-DSA (Module Lattice-based DSA — NIST FIPS 204)
 * ============================================================== */

#ifndef NEXTSSL_BUILD_LITE
NEXTSSL_API int nextssl_root_pqc_sign_mldsa44_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_mldsa44_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_mldsa44_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_mldsa65_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_mldsa65_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_mldsa65_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);
#endif /* NEXTSSL_BUILD_LITE */

NEXTSSL_API int nextssl_root_pqc_sign_mldsa87_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_mldsa87_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_mldsa87_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

/* ================================================================
 * Falcon
 * ============================================================== */

#ifndef NEXTSSL_BUILD_LITE

NEXTSSL_API int nextssl_root_pqc_sign_falcon512_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_falcon512_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_falcon512_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_falcon1024_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_falcon1024_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_falcon1024_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_falconpad512_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_falconpad512_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_falconpad512_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_falconpad1024_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_falconpad1024_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_falconpad1024_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

/* ================================================================
 * SPHINCS+-SHA2
 * ============================================================== */

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_128f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_128f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_128f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_128s_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_128s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_128s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_192f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_192f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_192f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_192s_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_192s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_192s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_256f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_256f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_256f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_256s_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_256s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_sha2_256s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

/* ================================================================
 * SPHINCS+-SHAKE
 * ============================================================== */

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_128f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_128f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_128f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_128s_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_128s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_128s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_192f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_192f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_192f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_192s_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_192s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_192s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_256f_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_256f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_256f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_256s_keygen(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_256s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
NEXTSSL_API int nextssl_root_pqc_sign_sphincs_shake_256s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

#endif /* NEXTSSL_BUILD_LITE */

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ROOT_PQC_SIGN_H */
