/* ecdsa_recoverable.c — Recoverable ECDSA on secp256k1 (SEC1v2 §4.1.6)
 *
 * TODO: Requires bitcoin-core/secp256k1 backend with ENABLE_MODULE_RECOVERY.
 *       Reference implementation: examples/c/ecdsa_recoverable/
 *       Clone https://github.com/bitcoin-core/secp256k1 into _secp256k1/
 *       and build with -DSECP256K1_ENABLE_MODULE_RECOVERY=1.
 */
#include "ecdsa_recoverable.h"
#include "../secp256k1/secp256k1.h"
#include <string.h>

#ifdef HAVE_SECP256K1_BACKEND
#  include "../_secp256k1/secp256k1_shim.h"
#endif

int ecdsa_recoverable_sign(const uint8_t privkey[32],
                            const uint8_t msg_hash[32],
                            uint8_t       sig[ECDSA_REC_SIG_SIZE])
{
    if (!privkey || !msg_hash || !sig) return -1;
#ifdef HAVE_SECP256K1_BACKEND
    return secp256k1_shim_sign_recoverable(privkey, msg_hash, sig);
#else
    /* Stub until backend is wired */
    (void)privkey; (void)msg_hash; (void)sig;
    return -1;
#endif
}

int ecdsa_recoverable_verify(const uint8_t msg_hash[32],
                              const uint8_t sig[ECDSA_REC_SIG_SIZE],
                              uint8_t       pubkey[65])
{
    if (!msg_hash || !sig || !pubkey) return -1;
#ifdef HAVE_SECP256K1_BACKEND
    return secp256k1_shim_recover_pubkey(msg_hash, sig, pubkey);
#else
    return -1;
#endif
}

int ecdsa_recoverable_verify_against_pubkey(
        const uint8_t *pubkey,   size_t pub_len,
        const uint8_t  msg_hash[32],
        const uint8_t  sig[ECDSA_REC_SIG_SIZE])
{
    if (!pubkey || !msg_hash || !sig) return -1;

    /* Recover public key from signature and compare */
    uint8_t recovered[65];
    if (ecdsa_recoverable_verify(msg_hash, sig, recovered) != 0) return -1;

    /* Compare uncompressed public keys */
    if (pub_len == 65) {
        return (memcmp(pubkey, recovered, 65) == 0) ? 0 : -1;
    }
    /* Compressed: compare x-coordinate only (bytes 1..32) */
    if (pub_len == 33) {
        return (memcmp(pubkey + 1, recovered + 1, 32) == 0) ? 0 : -1;
    }
    return -1;
}
