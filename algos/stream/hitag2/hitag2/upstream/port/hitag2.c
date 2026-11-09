/* C translation of hitag.py (HITAG2 cipher, "Implemented by Aram Verstegen"), from the repository
 * https://github.com/jackiecan/hitag2 (no license stated). Line-by-line port, see ../ORIGIN.md. */
#include "hitag2.h"

/* i4: bits a,b,c,d of x combined into a 4-bit number abcd */
static unsigned i4(uint64_t x, int a, int b, int c, int d) {
    return (unsigned)((((x >> a) & 1) * 8) + ((x >> b) & 1) * 4 + ((x >> c) & 1) * 2 + ((x >> d) & 1));
}

static unsigned f20_4(uint64_t state) { return (0x3c65u >> i4(state, 34, 43, 44, 46)) & 1; }
static unsigned f20_3(uint64_t state) { return (0xee5u >> i4(state, 28, 29, 31, 33)) & 1; }
static unsigned f20_2(uint64_t state) { return (0xee5u >> i4(state, 17, 21, 23, 26)) & 1; }
static unsigned f20_1(uint64_t state) { return (0xee5u >> i4(state, 8, 12, 14, 15)) & 1; }
static unsigned f20_0(uint64_t state) { return (0x3c65u >> i4(state, 2, 3, 5, 6)) & 1; }

static unsigned f20_last(unsigned s0, unsigned s1, unsigned s2, unsigned s3, unsigned s4) {
    return (0xdd3929bu >> ((s0 * 16) + (s1 * 8) + (s2 * 4) + (s3 * 2) + (s4 * 1))) & 1;
}

static unsigned f20(uint64_t state) {
    return f20_last(f20_0(state), f20_1(state), f20_2(state), f20_3(state), f20_4(state));
}

uint64_t hitag2_init(uint64_t key, uint32_t uid, uint32_t nonce) {
    uint64_t state = 0;
    unsigned curr_f20, curr_nonce_bit, curr_key_bit, final_fb_bit;
    int i;

    for (i = 32; i < 48; i++)
        state = (state << 1) | ((key >> i) & 1);
    for (i = 0; i < 32; i++)
        state = (state << 1) | (((uint64_t)uid >> i) & 1);

    for (i = 0; i < 32; i++) {
        curr_f20 = f20(state);
        curr_nonce_bit = (nonce >> (31 - i)) & 1;
        curr_key_bit = (unsigned)((key >> (31 - i)) & 1);
        final_fb_bit = curr_f20 ^ curr_nonce_bit ^ curr_key_bit;
        state = (state >> 1) | ((uint64_t)final_fb_bit << 47);
    }
    return state;
}

static unsigned lfsr_feedback(uint64_t state) {
    return (unsigned)(((state >> 0) ^ (state >> 2) ^ (state >> 3)
                       ^ (state >> 6) ^ (state >> 7) ^ (state >> 8)
                       ^ (state >> 16) ^ (state >> 22) ^ (state >> 23)
                       ^ (state >> 26) ^ (state >> 30) ^ (state >> 41)
                       ^ (state >> 42) ^ (state >> 43) ^ (state >> 46)
                       ^ (state >> 47)) & 1);
}

static uint64_t lfsr(uint64_t state) {
    return (state >> 1) + ((uint64_t)lfsr_feedback(state) << 47);
}

void hitag2_keystream(uint64_t *state, uint8_t *out, size_t nbits) {
    size_t i;
    for (i = 0; i < (nbits + 7) / 8; i++) out[i] = 0;
    for (i = 0; i < nbits; i++) {
        unsigned keystream_bit = f20(*state);
        out[i / 8] |= (uint8_t)(keystream_bit << (7 - (i % 8)));
        *state = lfsr(*state);
    }
}
