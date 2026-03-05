/**
 * @file root/nextssl_root.c (Lite)
 * @brief NextSSL Lite Root — Build anchor / compatibility shim
 *
 * This file exists solely as a compilation anchor so that build systems
 * that reference nextssl_root.c directly continue to produce a valid object.
 *
 * All algorithm implementations have been moved into sub-module files:
 *   hash/root_hash.c          — SHA-256, SHA-512, BLAKE3, Argon2id
 *   core/root_aead.c          — AES-256-GCM, ChaCha20-Poly1305
 *   core/root_ecc.c           — Ed25519, X25519
 *   pqc/root_pqc_kem.c        — ML-KEM-1024
 *   pqc/root_pqc_sign.c       — ML-DSA-87
 *   pow/root_pow.c            — PoW (sha256/sha512/blake3/argon2id)
 *
 * All backwards-compatible flat-name aliases (nextssl_root_sha256, etc.)
 * are implemented as inline functions in nextssl_root.h — no separate .c
 * definitions are required.
 *
 * Build systems should compile EACH sub-module .c independently, or add
 * this stub to satisfy legacy build rules (it compiles cleanly to an empty
 * translation unit).
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "nextssl_root.h"

/* intentionally empty — all symbols live in the sub-module .c files */

