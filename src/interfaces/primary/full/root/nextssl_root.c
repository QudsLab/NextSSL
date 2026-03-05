/**
 * @file root/nextssl_root.c
 * @brief NextSSL Full -- Root dispatcher (compile-check stub).
 *
 * All algorithm implementations now live in the sub-files:
 *   hash/root_hash.c      -- SHA-224/256/512, BLAKE2b/2s/3, SHA-3, Keccak,
 *                            SHAKE-128/256, Argon2id/d/i
 *   core/root_aead.c      -- AES-GCM/CCM/EAX/GCM-SIV/OCB/SIV, Poly1305,
 *                            ChaCha20-Poly1305
 *   core/root_cipher.c    -- AES-CBC/CFB/CTR/OFB/XTS/KW/FPE
 *   core/root_ecc.c       -- Ed25519, X25519, X448, Ristretto255, Elligator2
 *   core/root_mac.c       -- AES-CMAC, SipHash-2-4
 *   pqc/root_pqc_kem.c    -- ML-KEM-512/768/1024, HQC-128/192/256,
 *                            Classic McEliece x10 variants
 *   pqc/root_pqc_sign.c   -- ML-DSA-44/65/87, Falcon x4,
 *                            SPHINCS+-SHA2 x6, SPHINCS+-SHAKE x6
 *   legacy/root_legacy.c  -- alive: SHA-1/MD5/RIPEMD-160/Whirlpool/NT-Hash/
 *                                   AES-ECB
 *                            unsafe: SHA-0/MD2/MD4/HAS-160/RIPEMD-128/256/320
 *   radix/root_radix.c    -- Base16/32/58/64/64url encode+decode
 *
 * This file intentionally contains no function definitions.
 * It is kept as the build anchor for the root module and ensures the umbrella
 * header compiles cleanly as a translation unit.
 *
 * Build system: compile ALL of the above .c files plus this file.
 * Do NOT compile the old nextssl_root.c implementations -- they have been
 * replaced by the sub-files listed above.
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "nextssl_root.h"  /* umbrella -- compile-checks all sub-headers */