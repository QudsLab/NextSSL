/* x3dh.c — Extended Triple Diffie-Hellman (Signal X3DH)
 *
 * Uses X25519 for all DH operations and HKDF-SHA256 for key derivation.
 * Reference: https://signal.org/docs/specifications/x3dh/
 */
#include "x3dh.h"
#include "../../kdf/hkdf/hkdf.h"
#include <string.h>

/* x25519: existing function from _ed25519 backend */
extern int x25519(uint8_t out[32], const uint8_t k[32], const uint8_t u[32]);

/* X3DH KDF: HKDF-SHA256 with the X3DH prefix string */
static int x3dh_kdf(const uint8_t *ikm, size_t ikm_len, uint8_t out[32])
{
    /* X3DH info string per spec §2.2 */
    static const uint8_t info[] = "X3DH";
    /* salt: 32 zero bytes */
    static const uint8_t salt[32] = {0};
    return hkdf_ex(NULL /* SHA-256 default */, salt, 32, ikm, ikm_len,
                   (const uint8_t *)info, sizeof(info) - 1, out, 32);
}

/* Concatenate DH results and derive shared key */
static int x3dh_derive(const uint8_t *dh_results, size_t total_len,
                        uint8_t sk[32])
{
    /* X3DH §3.3: SK = KDF(F || DH1 || DH2 || DH3 [|| DH4])
     * F = 0xFF bytes (32 of them) — X3DH curve25519 prefix */
    static const uint8_t F[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    };

    uint8_t ikm[32 + 128]; /* F(32) + up to 4 × DH results(32) */
    memcpy(ikm, F, 32);
    size_t ikm_len = 32;
    if (total_len > 128) total_len = 128;
    memcpy(ikm + ikm_len, dh_results, total_len);
    ikm_len += total_len;

    return x3dh_kdf(ikm, ikm_len, sk);
}

int x3dh_sender_shared_key(
        const uint8_t ik_a_priv[X3DH_KEY_SIZE],
        const uint8_t ek_a_priv[X3DH_KEY_SIZE],
        const uint8_t ik_b_pub[X3DH_KEY_SIZE],
        const uint8_t spk_b_pub[X3DH_KEY_SIZE],
        const uint8_t *opk_b_pub,
        uint8_t        sk[X3DH_SK_SIZE])
{
    if (!ik_a_priv || !ek_a_priv || !ik_b_pub || !spk_b_pub || !sk) return -1;

    uint8_t dh[4][32];
    if (x25519(dh[0], ik_a_priv, spk_b_pub) != 0) return -1;  /* DH1 */
    if (x25519(dh[1], ek_a_priv, ik_b_pub)  != 0) return -1;  /* DH2 */
    if (x25519(dh[2], ek_a_priv, spk_b_pub) != 0) return -1;  /* DH3 */

    size_t n = 3;
    if (opk_b_pub) {
        if (x25519(dh[3], ek_a_priv, opk_b_pub) != 0) return -1; /* DH4 */
        n = 4;
    }

    uint8_t concat[4 * 32];
    for (size_t i = 0; i < n; i++) memcpy(concat + i * 32, dh[i], 32);
    int ret = x3dh_derive(concat, n * 32, sk);
    memset(dh, 0, sizeof(dh));
    memset(concat, 0, sizeof(concat));
    return ret;
}

int x3dh_recipient_shared_key(
        const uint8_t ik_b_priv[X3DH_KEY_SIZE],
        const uint8_t spk_b_priv[X3DH_KEY_SIZE],
        const uint8_t *opk_b_priv,
        const uint8_t ik_a_pub[X3DH_KEY_SIZE],
        const uint8_t ek_a_pub[X3DH_KEY_SIZE],
        uint8_t        sk[X3DH_SK_SIZE])
{
    if (!ik_b_priv || !spk_b_priv || !ik_a_pub || !ek_a_pub || !sk) return -1;

    uint8_t dh[4][32];
    if (x25519(dh[0], spk_b_priv, ik_a_pub)  != 0) return -1;  /* DH1 */
    if (x25519(dh[1], ik_b_priv,  ek_a_pub)  != 0) return -1;  /* DH2 */
    if (x25519(dh[2], spk_b_priv, ek_a_pub)  != 0) return -1;  /* DH3 */

    size_t n = 3;
    if (opk_b_priv) {
        if (x25519(dh[3], opk_b_priv, ek_a_pub) != 0) return -1; /* DH4 */
        n = 4;
    }

    uint8_t concat[4 * 32];
    for (size_t i = 0; i < n; i++) memcpy(concat + i * 32, dh[i], 32);
    int ret = x3dh_derive(concat, n * 32, sk);
    memset(dh, 0, sizeof(dh));
    memset(concat, 0, sizeof(concat));
    return ret;
}
