/* noise_kdf.h — Noise Protocol Framework KDF functions (Noise spec rev 34)
 *
 * The Noise protocol uses a CipherState, SymmetricState, and HandshakeState.
 * This module exposes the low-level KDF primitives used in the SymmetricState:
 *
 *   HKDF(chaining_key, input_key_material) →
 *       (output1, output2[, output3])
 *   where HKDF uses:
 *     temp_key  = HMAC-Hash(chaining_key, input_key_material)
 *     output1   = HMAC-Hash(temp_key, 0x01)
 *     output2   = HMAC-Hash(temp_key, output1 || 0x02)
 *     output3   = HMAC-Hash(temp_key, output2 || 0x03)  [if 3 outputs]
 *
 * Reference: https://noiseprotocol.org/noise.html §5.2
 */
#ifndef NEXTSSL_NOISE_KDF_H
#define NEXTSSL_NOISE_KDF_H

#include <stdint.h>
#include <stddef.h>

#define NOISE_HASH_LEN  32u  /* SHA-256 = 32 bytes */

/* noise_hkdf2 — Derive 2 outputs from chaining_key + ikm.
 * ck, ikm: NOISE_HASH_LEN bytes each
 * out1, out2: NOISE_HASH_LEN bytes each (output)
 * Returns 0 on success. */
int noise_hkdf2(const uint8_t ck[NOISE_HASH_LEN],
                 const uint8_t *ikm, size_t ikm_len,
                 uint8_t out1[NOISE_HASH_LEN],
                 uint8_t out2[NOISE_HASH_LEN]);

/* noise_hkdf3 — Derive 3 outputs.
 * out3: third NOISE_HASH_LEN output (e.g. for SplitHandshakeState). */
int noise_hkdf3(const uint8_t ck[NOISE_HASH_LEN],
                 const uint8_t *ikm, size_t ikm_len,
                 uint8_t out1[NOISE_HASH_LEN],
                 uint8_t out2[NOISE_HASH_LEN],
                 uint8_t out3[NOISE_HASH_LEN]);

#endif /* NEXTSSL_NOISE_KDF_H */
