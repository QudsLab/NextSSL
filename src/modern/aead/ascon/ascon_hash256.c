/* ascon_hash256.c — Ascon-Hash256 (SP 800-232) */
#include "ascon_hash256.h"
#include "ascon_core.h"
#include <string.h>

#define PA 12
#define PB  8   /* Hash256 uses pb=8 */
#define RATE 8  /* 64-bit rate for hash mode */

/* IV for Ascon-Hash256 */
#define ASCON_HASH256_IV 0x00400c0000000100ULL

void ascon_hash256(const uint8_t *msg, size_t msglen, uint8_t out[ASCON_HASH256_DIGEST_LEN])
{
    ascon_state_t s;
    memset(&s, 0, sizeof(s));
    s.x[0] = ASCON_HASH256_IV;
    ascon_permute(&s, PA);

    /* Absorb */
    while (msglen >= RATE) {
        s.x[0] ^= ascon_load64(msg);
        ascon_permute(&s, PB);
        msg += RATE; msglen -= RATE;
    }
    uint8_t buf[RATE] = {0};
    memcpy(buf, msg, msglen);
    buf[msglen] = 0x80;
    s.x[0] ^= ascon_load64(buf);
    ascon_permute(&s, PA);

    /* Squeeze 32 bytes */
    ascon_store64(out,      s.x[0]);
    ascon_permute(&s, PB);
    ascon_store64(out +  8, s.x[0]);
    ascon_permute(&s, PB);
    ascon_store64(out + 16, s.x[0]);
    ascon_permute(&s, PB);
    ascon_store64(out + 24, s.x[0]);
}
