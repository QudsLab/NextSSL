#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H

// Unified Crypto Core Header
// This header exposes the core cryptographic primitives and protocols.

#ifdef __cplusplus
extern "C" {
#endif

// --- Hash Primitives ---
#include "../primitives/hash/fast/blake3/blake3.h"
#include "../primitives/hash/fast/sha256/sha256.h"
#include "../primitives/hash/sponge_xof/sha3/sha3.h"

// --- AEAD Primitives ---
#include "../primitives/aead/aes_gcm/aes_gcm.h"
#include "../primitives/aead/chacha20_poly1305/monocypher.h"

// --- ECC Primitives ---
#include "../primitives/ecc/ed25519/ed25519.h"
#include "../primitives/ecc/curve448/curve448.h"

// --- PoW Protocol ---
#include "../utils/pow/pow.h"

// Note: For advanced or legacy algorithms, include their specific headers directly.

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_CORE_H
