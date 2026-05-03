/* ascon_core.c — Ascon permutation (SP 800-232, based on reference implementation) */
#include "ascon_core.h"
#include <string.h>

/* Round constants (12 rounds, indexed 0..11) */
static const uint64_t RC[12] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

/* Rotation right of a 64-bit word */
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void ascon_round(ascon_state_t *s, uint64_t C)
{
    uint64_t t0, t1, t2, t3, t4;

    /* Addition of round constant to x2 */
    s->x[2] ^= C;

    /* Substitution layer (Ascon S-box, applied bit-slice) */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    t0 = s->x[0]; t1 = s->x[1]; t2 = s->x[2]; t3 = s->x[3]; t4 = s->x[4];
    t0 = ~t0; t1 = ~t1; t2 = ~t2; t3 = ~t3; t4 = ~t4;
    t0 &= s->x[1]; t1 &= s->x[2]; t2 &= s->x[3]; t3 &= s->x[4]; t4 &= s->x[0];
    s->x[0] ^= t1;  s->x[1] ^= t2;  s->x[2] ^= t3;
    s->x[3] ^= t4;  s->x[4] ^= t0;
    s->x[1] ^= s->x[0]; s->x[0] ^= s->x[4]; s->x[3] ^= s->x[2];
    s->x[2] = ~s->x[2];

    /* Linear diffusion layer */
    s->x[0] ^= ROR64(s->x[0], 19) ^ ROR64(s->x[0], 28);
    s->x[1] ^= ROR64(s->x[1], 61) ^ ROR64(s->x[1], 39);
    s->x[2] ^= ROR64(s->x[2],  1) ^ ROR64(s->x[2],  6);
    s->x[3] ^= ROR64(s->x[3], 10) ^ ROR64(s->x[3], 17);
    s->x[4] ^= ROR64(s->x[4],  7) ^ ROR64(s->x[4], 41);
}

void ascon_permute(ascon_state_t *s, int rounds)
{
    int start = 12 - rounds;
    for (int i = start; i < 12; i++)
        ascon_round(s, RC[i]);
}

uint64_t ascon_load64(const uint8_t *b)
{
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48)
         | ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32)
         | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16)
         | ((uint64_t)b[6] <<  8) |  (uint64_t)b[7];
}

void ascon_store64(uint8_t *b, uint64_t v)
{
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >>  8); b[7] = (uint8_t)(v      );
}

void ascon_pad(ascon_state_t *s, int lane, size_t len)
{
    /* Set bit at position (len * 8) from MSB of lane */
    s->x[lane] ^= ((uint64_t)0x80 << (56 - (len % 8) * 8));
}
