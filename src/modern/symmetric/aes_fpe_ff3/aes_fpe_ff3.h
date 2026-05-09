/* aes_fpe_ff3.h — AES Format-Preserving Encryption FF3-1 (SP 800-38G Rev 1)
 *
 * FF3-1 is a Feistel-based FPE mode using a 7-byte (56-bit) tweak and AES
 * in reverse-key mode.  It preserves radix and length of the plaintext numeral
 * string.
 *
 * Constraints (SP 800-38G Rev 1 §5.2):
 *   2 ≤ radix ≤ 2^16
 *   minlen ≥ ceil(log_radix(1000000)) [at least 6 digits for radix=10]
 *   maxlen ≤ 2 * floor(log_radix(2^96))
 *   2 ≤ len ≤ maxlen
 *
 * Both numeral arrays contain values in [0, radix-1].
 * The key must be 16, 24, or 32 bytes (AES-128/192/256).
 * The tweak must be exactly 7 bytes.
 *
 * Returns 0 on success, -1 on invalid parameters.
 */
#ifndef NEXTSSL_AES_FPE_FF3_H
#define NEXTSSL_AES_FPE_FF3_H

#include <stdint.h>
#include <stddef.h>

/* Maximum numeral-string length supported (SP 800-38G §5.2 with AES-256) */
#define AES_FF3_MAX_LEN  192u
#define AES_FF3_TWEAK_LEN 7u

/* Encrypt a numeral string X (len values in [0, radix-1]) to ciphertext Y.
 *
 * key     : AES key (16/24/32 bytes; keylen must match)
 * keylen  : key length in bytes
 * tweak   : 7-byte tweak (must not repeat for the same key+plaintext)
 * radix   : numeral base (2–65536)
 * X       : input numeral string (X[i] in [0, radix-1])
 * Y       : output numeral string (same length)
 * len     : number of numerals
 *
 * Returns 0 on success, -1 on invalid parameters.
 */
int aes_ff3_encrypt(const uint8_t *key,   size_t keylen,
                    const uint8_t  tweak[AES_FF3_TWEAK_LEN],
                    uint32_t       radix,
                    const uint32_t *X,    size_t len,
                    uint32_t       *Y);

/* Decrypt a numeral string Y to plaintext X.
 * Same parameters as aes_ff3_encrypt; Y and X are reversed roles.
 * Returns 0 on success, -1 on invalid parameters.
 */
int aes_ff3_decrypt(const uint8_t *key,   size_t keylen,
                    const uint8_t  tweak[AES_FF3_TWEAK_LEN],
                    uint32_t       radix,
                    const uint32_t *Y,    size_t len,
                    uint32_t       *X);

#endif /* NEXTSSL_AES_FPE_FF3_H */
