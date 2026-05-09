/* secp256k1.c — secp256k1 surface implementation
 *
 * NOTE: Wire to bitcoin-core/secp256k1 library backend.
 * Clone https://github.com/bitcoin-core/secp256k1 into
 * src/modern/asymmetric/_secp256k1/ and add to CMakeLists.txt.
 *
 * Until wired, functions return -1 for actual crypto operations but
 * the API surface is correct and ready to link.
 *
 * Reference: examples/c/secp256k1/ (clone bitcoin-core/secp256k1 there)
 */
#include "secp256k1.h"
#include <string.h>

/* Forward declarations for the _secp256k1 backend (bitcoin-core API shim).
 * These will be resolved once the backend is added to CMakeLists.txt. */

#ifdef HAVE_SECP256K1_BACKEND
#  include "../_secp256k1/secp256k1_shim.h"
#endif

extern int rng_fill(void *buf, size_t len);

int secp256k1_keygen(uint8_t private_key[SECP256K1_PRIVKEY_SIZE],
                     uint8_t public_key[SECP256K1_PUBKEY_UNCOMPRESSED_SIZE])
{
    if (!private_key || !public_key) return -1;
#ifdef HAVE_SECP256K1_BACKEND
    return secp256k1_shim_keygen(private_key, public_key);
#else
    /* Generate private key as random 32-byte scalar (reject-sample) */
    if (rng_fill(private_key, SECP256K1_PRIVKEY_SIZE) != 0) return -1;
    return secp256k1_pubkey_from_privkey(private_key, 0, public_key,
                                         &(size_t){SECP256K1_PUBKEY_UNCOMPRESSED_SIZE});
#endif
}

int secp256k1_pubkey_from_privkey(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                                   int compressed,
                                   uint8_t *pubkey, size_t *pubkey_len)
{
    if (!privkey || !pubkey || !pubkey_len) return -1;
#ifdef HAVE_SECP256K1_BACKEND
    return secp256k1_shim_pubkey(privkey, compressed, pubkey, pubkey_len);
#else
    (void)compressed;
    /* Stub: not available without backend */
    return -1;
#endif
}

int secp256k1_ecdh(const uint8_t *their_pubkey, size_t pub_len,
                   const uint8_t  our_privkey[SECP256K1_PRIVKEY_SIZE],
                   uint8_t        shared[32])
{
    if (!their_pubkey || !our_privkey || !shared) return -1;
    (void)pub_len;
#ifdef HAVE_SECP256K1_BACKEND
    return secp256k1_shim_ecdh(their_pubkey, pub_len, our_privkey, shared);
#else
    return -1;
#endif
}

int secp256k1_sign(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                   const uint8_t msg_hash[32],
                   uint8_t       sig_r[32],
                   uint8_t       sig_s[32])
{
    if (!privkey || !msg_hash || !sig_r || !sig_s) return -1;
#ifdef HAVE_SECP256K1_BACKEND
    return secp256k1_shim_sign(privkey, msg_hash, sig_r, sig_s);
#else
    return -1;
#endif
}

int secp256k1_verify(const uint8_t *pubkey, size_t pub_len,
                     const uint8_t  msg_hash[32],
                     const uint8_t  sig_r[32],
                     const uint8_t  sig_s[32])
{
    if (!pubkey || !msg_hash || !sig_r || !sig_s) return -1;
    (void)pub_len;
#ifdef HAVE_SECP256K1_BACKEND
    return secp256k1_shim_verify(pubkey, pub_len, msg_hash, sig_r, sig_s);
#else
    return -1;
#endif
}
