/* ascon_aead128.c — Ascon-AEAD128 (SP 800-232) */
#include "ascon_aead128.h"
#include "ascon_core.h"
#include <string.h>

/* IV for Ascon-AEAD128: key_len(8b) || tag_len(8b) || pa(8b) || pb(8b) || rate(8b) || ... */
#define ASCON_AEAD128_IV  0x00001000808c0001ULL
#define PA 12
#define PB  6
#define RATE 16  /* 128-bit rate */

static void absorb_ad(ascon_state_t *s, const uint8_t *ad, size_t adlen)
{
    while (adlen >= RATE) {
        s->x[0] ^= ascon_load64(ad);
        s->x[1] ^= ascon_load64(ad + 8);
        ascon_permute(s, PB);
        ad += RATE; adlen -= RATE;
    }
    /* Final partial block */
    uint8_t buf[RATE] = {0};
    memcpy(buf, ad, adlen);
    buf[adlen] = 0x80;
    s->x[0] ^= ascon_load64(buf);
    s->x[1] ^= ascon_load64(buf + 8);
    ascon_permute(s, PB);
    /* Domain separation */
    s->x[4] ^= 1ULL;
}

int ascon_aead128_encrypt(const uint8_t key[ASCON_AEAD128_KEY_LEN],
                           const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                           const uint8_t *ad,    size_t adlen,
                           const uint8_t *pntxt, size_t pntxtlen,
                           uint8_t       *crtxt)
{
    ascon_state_t s;

    /* Initialization */
    s.x[0] = ASCON_AEAD128_IV;
    s.x[1] = ascon_load64(key);
    s.x[2] = ascon_load64(key + 8);
    s.x[3] = ascon_load64(nonce);
    s.x[4] = ascon_load64(nonce + 8);
    ascon_permute(&s, PA);
    s.x[3] ^= ascon_load64(key);
    s.x[4] ^= ascon_load64(key + 8);

    /* Process AD */
    if (adlen > 0)
        absorb_ad(&s, ad, adlen);

    /* Encrypt plaintext */
    const uint8_t *p = pntxt;
    uint8_t       *c = crtxt;
    size_t         remaining = pntxtlen;
    while (remaining >= RATE) {
        s.x[0] ^= ascon_load64(p);
        s.x[1] ^= ascon_load64(p + 8);
        ascon_store64(c,     s.x[0]);
        ascon_store64(c + 8, s.x[1]);
        ascon_permute(&s, PB);
        p += RATE; c += RATE; remaining -= RATE;
    }
    /* Final partial plaintext block */
    uint8_t buf[RATE] = {0};
    memcpy(buf, p, remaining);
    buf[remaining] = 0x80;
    s.x[0] ^= ascon_load64(buf);
    s.x[1] ^= ascon_load64(buf + 8);
    uint8_t cbuf[RATE];
    ascon_store64(cbuf,     s.x[0]);
    ascon_store64(cbuf + 8, s.x[1]);
    memcpy(c, cbuf, remaining);
    c += remaining;

    /* Finalization */
    s.x[2] ^= ascon_load64(key);
    s.x[3] ^= ascon_load64(key + 8);
    ascon_permute(&s, PA);
    s.x[3] ^= ascon_load64(key);
    s.x[4] ^= ascon_load64(key + 8);

    /* Tag = s.x[3] || s.x[4] */
    ascon_store64(c,     s.x[3]);
    ascon_store64(c + 8, s.x[4]);
    return 0;
}

int ascon_aead128_decrypt(const uint8_t key[ASCON_AEAD128_KEY_LEN],
                           const uint8_t nonce[ASCON_AEAD128_NONCE_LEN],
                           const uint8_t *ad,     size_t adlen,
                           const uint8_t *crtxt,  size_t crtxtlen,
                           uint8_t       *pntxt)
{
    if (crtxtlen < ASCON_AEAD128_TAG_LEN) return -1;
    size_t pntxtlen = crtxtlen - ASCON_AEAD128_TAG_LEN;

    ascon_state_t s;

    /* Initialization */
    s.x[0] = ASCON_AEAD128_IV;
    s.x[1] = ascon_load64(key);
    s.x[2] = ascon_load64(key + 8);
    s.x[3] = ascon_load64(nonce);
    s.x[4] = ascon_load64(nonce + 8);
    ascon_permute(&s, PA);
    s.x[3] ^= ascon_load64(key);
    s.x[4] ^= ascon_load64(key + 8);

    /* Process AD */
    if (adlen > 0)
        absorb_ad(&s, ad, adlen);

    /* Decrypt ciphertext */
    const uint8_t *c = crtxt;
    uint8_t       *p = pntxt;
    size_t         remaining = pntxtlen;
    while (remaining >= RATE) {
        uint64_t c0 = ascon_load64(c), c1 = ascon_load64(c + 8);
        ascon_store64(p,     s.x[0] ^ c0);
        ascon_store64(p + 8, s.x[1] ^ c1);
        s.x[0] = c0; s.x[1] = c1;
        ascon_permute(&s, PB);
        c += RATE; p += RATE; remaining -= RATE;
    }
    /* Final partial block */
    uint8_t cbuf[RATE] = {0};
    memcpy(cbuf, c, remaining);
    uint64_t c0 = ascon_load64(cbuf), c1 = ascon_load64(cbuf + 8);
    uint8_t pbuf[RATE];
    ascon_store64(pbuf,     s.x[0] ^ c0);
    ascon_store64(pbuf + 8, s.x[1] ^ c1);
    memcpy(p, pbuf, remaining);
    /* Restore state for finalization */
    uint8_t tbuf[RATE] = {0};
    memcpy(tbuf, pbuf, remaining);
    tbuf[remaining] = 0x80;
    s.x[0] ^= ascon_load64(tbuf);
    s.x[1] ^= ascon_load64(tbuf + 8);
    c += remaining;

    /* Finalization */
    s.x[2] ^= ascon_load64(key);
    s.x[3] ^= ascon_load64(key + 8);
    ascon_permute(&s, PA);
    s.x[3] ^= ascon_load64(key);
    s.x[4] ^= ascon_load64(key + 8);

    /* Constant-time tag comparison */
    uint64_t t0 = ascon_load64(c), t1 = ascon_load64(c + 8);
    uint64_t diff = (s.x[3] ^ t0) | (s.x[4] ^ t1);
    return diff ? -1 : 0;
}
