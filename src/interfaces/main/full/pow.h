/**
 * @file pow.h
 * @brief Layer 3: High-level password hashing
 * @layer main
 * @category pow
 * @visibility public
 * 
 * Simple password hashing interface with secure defaults.
 * 
 * **Default algorithm:** Argon2id with OWASP 2023 parameters
 * 
 * @security Memory-hard, side-channel resistant
 * @example User authentication, password storage
 */

#ifndef NEXTSSL_MAIN_POW_H
#define NEXTSSL_MAIN_POW_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Hash password for storage (Argon2id default)
 * 
 * @param password User password
 * @param password_len Length of password
 * @param hash_output Output buffer for encoded hash (128 bytes minimum)
 * @param hash_output_len Size of output buffer
 * @return 0 on success, negative on error
 * 
 * @note Uses Argon2id with OWASP 2023 defaults (t=4, m=256MB, p=4)
 * @security Store the output hash string in your database
 * @example User registration: hash password before storing
 */
NEXTSSL_MAIN_API int nextssl_password_hash(
    const char *password, size_t password_len,
    char *hash_output, size_t hash_output_len);

/**
 * Verify password against stored hash (constant-time)
 * 
 * @param password User-entered password
 * @param password_len Length of password
 * @param stored_hash Hash from nextssl_password_hash()
 * @return 1 if match, 0 if mismatch, negative on error
 * 
 * @security Constant-time comparison prevents timing attacks
 * @example User login: verify entered password
 */
NEXTSSL_MAIN_API int nextssl_password_verify(
    const char *password, size_t password_len,
    const char *stored_hash);

/**
 * Hash password with custom strength level
 * 
 * @param password User password
 * @param password_len Length of password
 * @param strength Strength level: 1=low (fast), 2=medium, 3=high (secure)
 * @param hash_output Output buffer (128 bytes minimum)
 * @param hash_output_len Size of output buffer
 * @return 0 on success, negative on error
 * 
 * @note Strength 1: t=2, m=64MB (testing only)
 * @note Strength 2: t=3, m=128MB (legacy systems)
 * @note Strength 3: t=5, m=512MB (high security)
 */
NEXTSSL_MAIN_API int nextssl_password_hash_custom(
    const char *password, size_t password_len,
    int strength,
    char *hash_output, size_t hash_output_len);

#endif /* NEXTSSL_MAIN_POW_H */
