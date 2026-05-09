/* ecdh.c — ECDH dispatcher over P-256/P-384/P-521/X25519/X448 */
#include "ecdh.h"
#include "../p256/p256.h"
#include "../p384/p384.h"
#include "../p521/p521.h"
#include "../x448/x448.h"
#include <string.h>

/* x25519 is exposed by the existing ed25519 backend */
extern int x25519(uint8_t shared[32], const uint8_t scalar[32], const uint8_t point[32]);
extern int x25519_base(uint8_t public_key[32], const uint8_t scalar[32]);

size_t ecdh_private_key_size(ecdh_curve_t c)
{
    switch (c) {
        case ECDH_P256:   return 32;
        case ECDH_P384:   return 48;
        case ECDH_P521:   return 66;
        case ECDH_X25519: return 32;
        case ECDH_X448:   return 56;
    }
    return 0;
}

size_t ecdh_public_key_size(ecdh_curve_t c)
{
    switch (c) {
        case ECDH_P256:   return 64;  /* x(32)||y(32) uncompressed w/o 0x04 */
        case ECDH_P384:   return 96;
        case ECDH_P521:   return 132;
        case ECDH_X25519: return 32;
        case ECDH_X448:   return 56;
    }
    return 0;
}

size_t ecdh_shared_size(ecdh_curve_t c)
{
    switch (c) {
        case ECDH_P256:   return 32;
        case ECDH_P384:   return 48;
        case ECDH_P521:   return 66;
        case ECDH_X25519: return 32;
        case ECDH_X448:   return 56;
    }
    return 0;
}

int ecdh_keygen(ecdh_curve_t curve,
                uint8_t *private_key,
                uint8_t *public_key)
{
    if (!private_key || !public_key) return -1;
    switch (curve) {
        case ECDH_P256:   return p256_keygen(private_key, public_key);
        case ECDH_P384:   return p384_keygen(private_key, public_key);
        case ECDH_P521:   return p521_keygen(private_key, public_key);
        case ECDH_X25519: return x25519_base(public_key, private_key);
        case ECDH_X448:   return x448_keygen(private_key, public_key);
    }
    return -1;
}

int ecdh_shared_secret(ecdh_curve_t   curve,
                       const uint8_t *our_private,  size_t priv_len,
                       const uint8_t *their_public, size_t pub_len,
                       uint8_t       *shared,       size_t *shared_len)
{
    if (!our_private || !their_public || !shared || !shared_len) return -1;
    size_t need = ecdh_shared_size(curve);
    if (*shared_len < need) return -1;
    *shared_len = need;
    (void)priv_len; (void)pub_len;

    switch (curve) {
        case ECDH_P256:
            return p256_ecdh(their_public, our_private, shared);
        case ECDH_P384:
            return p384_ecdh(their_public, our_private, shared);
        case ECDH_P521:
            return p521_ecdh(their_public, our_private, shared);
        case ECDH_X25519:
            return x25519(shared, our_private, their_public);
        case ECDH_X448:
            return x448_scalarmult(shared, our_private, their_public);
    }
    return -1;
}
