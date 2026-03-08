/**
 * @file root/nextssl_root.h
 * @brief NextSSL Full -- Explicit-Algorithm (Root) Umbrella Interface
 *
 * Including this header signals that you are operating OUTSIDE the safe
 * default path.  Every function here bypasses the active profile entirely --
 * the algorithm is hardcoded in the function name.
 *
 * Who should use this:
 *   - Protocol implementors that must match an external algorithm requirement
 *   - Test harnesses verifying known-answer vectors for specific algorithms
 *   - Any code that cannot accept the profile-selected default
 *
 * Who should NOT use this for normal application code:
 *   - Use nextssl_hash(), nextssl_encrypt(), etc. (the profile-driven defaults)
 *
 * Usage:
 *   #include "nextssl.h"               // safe defaults
 *   #include "root/nextssl_root.h"     // explicit algorithms -- path is the warning
 *
 * To use a sub-group only:
 *   #include "root/hash/root_hash.h"
 *   #include "root/pqc/root_pqc_kem.h"
 *   etc.
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_FULL_ROOT_H
#define NEXTSSL_FULL_ROOT_H

/* ---- Sub-group headers (tree structure matching bin/ layout) ----------- */

#include "hash/root_hash.h"        /* SHA-224/256/512, BLAKE2b/2s/3,        */
                                   /* SHA-3-224/256/384/512, Keccak-256,     */
                                   /* SHAKE-128/256, Argon2id/d/i            */

#include "core/root_aead.h"        /* AES-GCM/CCM/EAX/GCM-SIV/OCB/SIV/     */
                                   /* Poly1305, ChaCha20-Poly1305            */

#ifndef NEXTSSL_BUILD_LITE
#include "core/root_cipher.h"      /* AES-CBC/CFB/CTR/OFB/XTS/KW/FPE        */
#endif /* NEXTSSL_BUILD_LITE */

#include "core/root_ecc.h"         /* Ed25519, X25519, X448/Curve448,        */
                                   /* Ristretto255, Elligator2               */

#ifndef NEXTSSL_BUILD_LITE
#include "core/root_mac.h"         /* AES-CMAC, SipHash-2-4                  */
#endif /* NEXTSSL_BUILD_LITE */

#include "pqc/root_pqc_kem.h"      /* ML-KEM-512/768/1024, HQC-128/192/256, */
                                   /* Classic McEliece x10 variants          */

#include "pqc/root_pqc_sign.h"     /* ML-DSA-44/65/87, Falcon x4,           */
                                   /* SPHINCS+-SHA2 x6, SPHINCS+-SHAKE x6   */

#ifndef NEXTSSL_BUILD_LITE
#include "legacy/root_legacy.h"    /* alive: SHA-1/MD5/RIPEMD-160/Whirlpool  */
                                   /*        NT-Hash/AES-ECB                 */
                                   /* unsafe: SHA-0/MD2/MD4/HAS-160/         */
                                   /*         RIPEMD-128/256/320             */
#endif /* NEXTSSL_BUILD_LITE */

#ifndef NEXTSSL_BUILD_LITE
#include "radix/root_radix.h"      /* Base16/32/58/64/64url encode+decode    */
#endif /* NEXTSSL_BUILD_LITE */

#include "pow/root_pow.h"           /* Server: generate_challenge, verify     */
                                   /* Client: parse, solve, limits, reject   */
                                   /* Core: encode/decode, difficulty, timer */

/* -------------------------------------------------------------------------
 * Backward-compatibility aliases
 *
 * These map the pre-tree function names (nextssl_root_<algo>) to the new
 * tree-structured names (nextssl_root_<group>_<algo>).
 * New code should use the tree names directly.
 * ---------------------------------------------------------------------- */

/* Hash */
#define nextssl_root_sha256       nextssl_root_hash_sha256
#define nextssl_root_sha512       nextssl_root_hash_sha512
#define nextssl_root_blake3       nextssl_root_hash_blake3
#define nextssl_root_sha1         nextssl_root_legacy_alive_sha1
#define nextssl_root_md5          nextssl_root_legacy_alive_md5

/* AEAD */
#define nextssl_root_aes256gcm_encrypt  nextssl_root_aead_aesgcm_encrypt
#define nextssl_root_aes256gcm_decrypt  nextssl_root_aead_aesgcm_decrypt
#define nextssl_root_chacha20_encrypt   nextssl_root_aead_chacha20_encrypt
#define nextssl_root_chacha20_decrypt   nextssl_root_aead_chacha20_decrypt

/* Classical asymmetric */
#define nextssl_root_x25519_keygen    nextssl_root_ecc_x25519_keygen
#define nextssl_root_x25519_exchange  nextssl_root_ecc_x25519_exchange
#define nextssl_root_ed25519_keygen   nextssl_root_ecc_ed25519_keygen
#define nextssl_root_ed25519_sign     nextssl_root_ecc_ed25519_sign
#define nextssl_root_ed25519_verify   nextssl_root_ecc_ed25519_verify

/* ---- Multi-profile / deterministic keygen shortcuts ------------------
 *
 * Use any keygen_new_*() factory to create a seed context, then call
 * these to derive keypairs for any user/session from that seed.
 *
 *   keygen_ctx_t *ctx = keygen_new_udbf(entropy, elen, "user_a");
 *   nextssl_root_keygen_ed25519(ctx, pk, sk); // user A's ed25519 key
 *   keygen_free(ctx);
 *
 * Keygen factories (keygen_new_random / _drbg / _password / _hash /
 * _kdf / _udbf / _hd) and keygen_free() are all available after
 * including this header (pulled in via root/core/root_ecc.h).
 * -------------------------------------------------------------------- */

/* ECC */
#define nextssl_root_keygen_ed25519           nextssl_root_ecc_ed25519_keygen_ctx
#define nextssl_root_keygen_x25519            nextssl_root_ecc_x25519_keygen_ctx
#define nextssl_root_keygen_ed448             nextssl_root_ecc_ed448_keygen_ctx
#define nextssl_root_keygen_x448              nextssl_root_ecc_x448_keygen_ctx
#define nextssl_root_keygen_elligator2        nextssl_root_ecc_elligator2_keygen_ctx

/* PQC — KEM */
#define nextssl_root_keygen_ml_kem_512        keygen_ml_kem_512
#define nextssl_root_keygen_ml_kem_768        keygen_ml_kem_768
#define nextssl_root_keygen_ml_kem_1024       keygen_ml_kem_1024
#define nextssl_root_keygen_hqc_128           keygen_hqc_128
#define nextssl_root_keygen_hqc_192           keygen_hqc_192
#define nextssl_root_keygen_hqc_256           keygen_hqc_256
#define nextssl_root_keygen_mceliece_348864   keygen_mceliece_348864
#define nextssl_root_keygen_mceliece_348864f  keygen_mceliece_348864f
#define nextssl_root_keygen_mceliece_460896   keygen_mceliece_460896
#define nextssl_root_keygen_mceliece_460896f  keygen_mceliece_460896f
#define nextssl_root_keygen_mceliece_6688128  keygen_mceliece_6688128
#define nextssl_root_keygen_mceliece_6688128f keygen_mceliece_6688128f
#define nextssl_root_keygen_mceliece_6960119  keygen_mceliece_6960119
#define nextssl_root_keygen_mceliece_6960119f keygen_mceliece_6960119f
#define nextssl_root_keygen_mceliece_8192128  keygen_mceliece_8192128
#define nextssl_root_keygen_mceliece_8192128f keygen_mceliece_8192128f

/* PQC — Signature */
#define nextssl_root_keygen_ml_dsa_44             keygen_ml_dsa_44
#define nextssl_root_keygen_ml_dsa_65             keygen_ml_dsa_65
#define nextssl_root_keygen_ml_dsa_87             keygen_ml_dsa_87
#define nextssl_root_keygen_falcon_512            keygen_falcon_512
#define nextssl_root_keygen_falcon_1024           keygen_falcon_1024
#define nextssl_root_keygen_falcon_padded_512     keygen_falcon_padded_512
#define nextssl_root_keygen_falcon_padded_1024    keygen_falcon_padded_1024
#define nextssl_root_keygen_sphincs_sha2_128f     keygen_sphincs_sha2_128f
#define nextssl_root_keygen_sphincs_sha2_128s     keygen_sphincs_sha2_128s
#define nextssl_root_keygen_sphincs_sha2_192f     keygen_sphincs_sha2_192f
#define nextssl_root_keygen_sphincs_sha2_192s     keygen_sphincs_sha2_192s
#define nextssl_root_keygen_sphincs_sha2_256f     keygen_sphincs_sha2_256f
#define nextssl_root_keygen_sphincs_sha2_256s     keygen_sphincs_sha2_256s
#define nextssl_root_keygen_sphincs_shake_128f    keygen_sphincs_shake_128f
#define nextssl_root_keygen_sphincs_shake_128s    keygen_sphincs_shake_128s
#define nextssl_root_keygen_sphincs_shake_192f    keygen_sphincs_shake_192f
#define nextssl_root_keygen_sphincs_shake_192s    keygen_sphincs_shake_192s
#define nextssl_root_keygen_sphincs_shake_256f    keygen_sphincs_shake_256f
#define nextssl_root_keygen_sphincs_shake_256s    keygen_sphincs_shake_256s

/* PQC KEM */
#define nextssl_root_mlkem768_keygen  nextssl_root_pqc_kem_mlkem768_keygen
#define nextssl_root_mlkem768_encaps  nextssl_root_pqc_kem_mlkem768_encaps
#define nextssl_root_mlkem768_decaps  nextssl_root_pqc_kem_mlkem768_decaps

/* PQC Sign */
#define nextssl_root_mldsa65_keygen  nextssl_root_pqc_sign_mldsa65_keygen
#define nextssl_root_mldsa65_sign    nextssl_root_pqc_sign_mldsa65_sign
#define nextssl_root_mldsa65_verify  nextssl_root_pqc_sign_mldsa65_verify
#define nextssl_root_mldsa87_keygen  nextssl_root_pqc_sign_mldsa87_keygen
#define nextssl_root_mldsa87_sign    nextssl_root_pqc_sign_mldsa87_sign
#define nextssl_root_mldsa87_verify  nextssl_root_pqc_sign_mldsa87_verify

/* KDF: old nextssl_root_argon2id had fixed t_cost/m_cost/par params.
 * New signature: nextssl_root_hash_argon2id(pw,pwlen,salt,slen,t,m,p,out,olen)
 * Use nextssl_root_hash_argon2id(pw,pwlen,salt,slen, 3,65536,4, out,olen)
 * to match the previous default parameters.                                */

#endif /* NEXTSSL_FULL_ROOT_H */