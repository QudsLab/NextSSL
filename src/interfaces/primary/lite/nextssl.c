/**
 * @file nextssl.c
 * @brief Lite variant unified API implementation (Layer 4)
 *
 * This is the ultra-simple wrapper for the lite variant.
 * Provides sensible defaults and minimal configuration.
 */

/* Mark this translation unit as building the DLL so NEXTSSL_API = dllexport */
#define NEXTSSL_BUILDING_DLL

#include "nextssl.h"
#include "../../main/lite/hash.h"
#include "../../main/lite/aead.h"
#include "../../main/lite/password.h"
#include "../../main/lite/keyexchange.h"
#include "../../main/lite/signature.h"
#include "../../main/lite/pqc.h"
#include "../../main/lite/pow.h"
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
/* RtlGenRandom = SystemFunction036 in advapi32.dll (always linked) */
BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
static int os_random(uint8_t *buf, size_t len) {
    return SystemFunction036(buf, (ULONG)len) ? 0 : -1;
}
#else
#  include <stdio.h>
static int os_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
}
#endif

// ============================================================================
// Hash Functions (defaults to SHA-256)
// ============================================================================

NEXTSSL_API int nextssl_hash(const uint8_t *data, size_t len, uint8_t *output) {
    return nextssl_lite_hash("SHA-256", data, len, output);
}

NEXTSSL_API int nextssl_hash_ex(const char *algorithm, const uint8_t *data, size_t len, uint8_t *output) {
    return nextssl_lite_hash(algorithm, data, len, output);
}

// ============================================================================
// Encryption Functions (defaults to AES-256-GCM)
// ============================================================================

NEXTSSL_API int nextssl_encrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plen,
    uint8_t *ciphertext
) {
    return nextssl_lite_aead_encrypt("AES-256-GCM", key, nonce, NULL, 0, plaintext, plen, ciphertext);
}

NEXTSSL_API int nextssl_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t clen,
    uint8_t *plaintext
) {
    return nextssl_lite_aead_decrypt("AES-256-GCM", key, nonce, NULL, 0, ciphertext, clen, plaintext);
}

NEXTSSL_API int nextssl_encrypt_ex(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plen,
    uint8_t *ciphertext
) {
    return nextssl_lite_aead_encrypt(algorithm, key, nonce, NULL, 0, plaintext, plen, ciphertext);
}

NEXTSSL_API int nextssl_decrypt_ex(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t clen,
    uint8_t *plaintext
) {
    return nextssl_lite_aead_decrypt(algorithm, key, nonce, NULL, 0, ciphertext, clen, plaintext);
}

// ============================================================================
// Password Hashing (Argon2id)
// ============================================================================

NEXTSSL_API int nextssl_password_hash(
    const uint8_t *password,
    size_t plen,
    const uint8_t *salt,
    uint8_t *output
) {
    return nextssl_lite_password_hash(password, plen, salt, 16, output);
}

NEXTSSL_API int nextssl_password_verify(
    const uint8_t *password,
    size_t plen,
    const uint8_t *salt,
    const uint8_t *expected_hash
) {
    return nextssl_lite_password_verify(password, plen, salt, 16, expected_hash);
}

// ============================================================================
// Key Exchange (defaults to X25519, can use Kyber1024)
// ============================================================================

NEXTSSL_API int nextssl_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    int pqc
) {
    if (pqc) {
        return nextssl_lite_kyber1024_keygen(public_key, secret_key);
    } else {
        return nextssl_lite_x25519_keygen(public_key, secret_key);
    }
}

NEXTSSL_API int nextssl_keyexchange(
    const uint8_t *my_secret,
    const uint8_t *their_public,
    uint8_t *shared_secret,
    uint8_t *ciphertext,
    int pqc
) {
    if (pqc) {
        if (!ciphertext) return -1;
        uint8_t ss[32];
        int ret = nextssl_lite_kyber1024_encaps(their_public, ciphertext, ss);
        if (ret == 0) memcpy(shared_secret, ss, 32);
        return ret;
    } else {
        return nextssl_lite_x25519_exchange(my_secret, their_public, shared_secret);
    }
}

NEXTSSL_API int nextssl_keyexchange_decaps(
    const uint8_t *ciphertext,
    const uint8_t *my_secret,
    uint8_t *shared_secret
) {
    return nextssl_lite_kyber1024_decaps(ciphertext, my_secret, shared_secret);
}

// ============================================================================
// Digital Signatures (defaults to Ed25519, can use Dilithium5)
// ============================================================================

NEXTSSL_API int nextssl_sign_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    int pqc
) {
    if (pqc) {
        return nextssl_lite_dilithium5_keygen(public_key, secret_key);
    } else {
        return nextssl_lite_ed25519_keygen(public_key, secret_key);
    }
}

NEXTSSL_API int nextssl_sign(
    const uint8_t *message,
    size_t mlen,
    const uint8_t *secret_key,
    uint8_t *signature,
    int pqc
) {
    if (pqc) {
        size_t sig_len;
        return nextssl_lite_dilithium5_sign(message, mlen, secret_key, signature, &sig_len);
    } else {
        return nextssl_lite_ed25519_sign(message, mlen, secret_key, signature);
    }
}

NEXTSSL_API int nextssl_verify(
    const uint8_t *message,
    size_t mlen,
    const uint8_t *signature,
    const uint8_t *public_key,
    int pqc
) {
    if (pqc) {
        return nextssl_lite_dilithium5_verify(message, mlen, signature, NEXTSSL_LITE_DILITHIUM5_SIGNATURE_SIZE, public_key);
    } else {
        return nextssl_lite_ed25519_verify(message, mlen, signature, public_key);
    }
}

// ============================================================================
// Proof-of-Work
// ============================================================================

NEXTSSL_API int nextssl_pow_solve(
    const uint8_t *challenge_data,
    size_t challenge_len,
    uint32_t difficulty,
    uint64_t *nonce,
    uint8_t *hash_output
) {
    if (challenge_len > 32) {
        return -1;
    }

    nextssl_lite_pow_challenge_t challenge;
    memset(&challenge, 0, sizeof(challenge));
    memcpy(challenge.challenge, challenge_data, challenge_len);
    challenge.difficulty = difficulty;
    challenge.timestamp = 0;

    nextssl_lite_pow_solution_t solution;
    memset(&solution, 0, sizeof(solution));
    int result = nextssl_lite_pow_solve(&challenge, &solution, 300);

    if (result == 0) {
        *nonce = 0;
        for (int i = 0; i < 8; i++) {
            *nonce |= (uint64_t)solution.nonce[i] << (i * 8);
        }
        memcpy(hash_output, solution.hash, 32);
    }

    return result;
}

NEXTSSL_API int nextssl_pow_verify(
    const uint8_t *challenge_data,
    size_t challenge_len,
    uint32_t difficulty,
    uint64_t nonce,
    const uint8_t *hash
) {
    if (challenge_len > 32) {
        return -1;
    }

    nextssl_lite_pow_challenge_t challenge;
    memset(&challenge, 0, sizeof(challenge));
    memcpy(challenge.challenge, challenge_data, challenge_len);
    challenge.difficulty = difficulty;
    challenge.timestamp = 0;

    nextssl_lite_pow_solution_t solution;
    memset(&solution, 0, sizeof(solution));
    for (int i = 0; i < 8 && i < 32; i++) {
        solution.nonce[i] = (nonce >> (i * 8)) & 0xFF;
    }
    memcpy(solution.hash, hash, 32);
    solution.iterations = 0;

    return nextssl_lite_pow_verify(&challenge, &solution);
}

// ============================================================================
// Utility Functions
// ============================================================================

NEXTSSL_API int nextssl_random(uint8_t *output, size_t len) {
    return os_random(output, len);
}

NEXTSSL_API const char* nextssl_version(void) {
    return "NextSSL v0.1.0-beta-lite";
}

NEXTSSL_API int nextssl_has_algorithm(const char *algorithm) {
    return nextssl_lite_hash_available(algorithm) ||
           nextssl_lite_pqc_available();
}

NEXTSSL_API int nextssl_list_algorithms(char *buffer, size_t size) {
    const char *algos = "SHA-256,SHA-512,BLAKE3,AES-256-GCM,ChaCha20-Poly1305,"
                        "Argon2id,HKDF,X25519,Kyber1024,Ed25519,Dilithium5";
    if (buffer && size > 0) {
        size_t n = strlen(algos);
        if (n >= size) n = size - 1;
        memcpy(buffer, algos, n);
        buffer[n] = '\0';
    }
    return 9;
}

NEXTSSL_API int nextssl_init(void) {
    return 0;
}

NEXTSSL_API void nextssl_cleanup(void) {
    /* Nothing to clean up for lite variant */
}
