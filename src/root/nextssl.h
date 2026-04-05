/* nextssl.h — Master Public Header for the NextSSL Library
 *
 * This is the ONLY header external consumers need to include.
 *
 * Provides unified access to all subsystems:
 *   - Hash algorithms (sha256, blake3, sha3, etc.)
 *   - Seed / key derivation (random + deterministic CTR-mode)
 *   - Modern cryptography (symmetric, AEAD, MAC, KDF, asymmetric)
 *   - Proof-of-Work (server challenge + client solver)
 *   - Post-Quantum Cryptography (ML-KEM, ML-DSA, Falcon, SPHINCS+, HQC, McEliece)
 *
 * Usage:
 *   #include "path/to/src/root/nextssl.h"
 */
#ifndef NEXTSSL_H
#define NEXTSSL_H

#include "nextssl_export.h"
#include "hash/root_hash.h"
#include "seed/root_seed.h"
#include "modern/root_modern.h"
#include "pow/root_pow.h"
#include "pqc/root_pqc.h"

#endif /* NEXTSSL_H */
