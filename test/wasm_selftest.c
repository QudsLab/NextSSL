/*
 * wasm_selftest.c
 * ───────────────
 * SHA-256 known-answer test used as the WASM module entry point.
 * Self-contained: uses a static SHA-256 so there are no external link deps.
 * Returns 0 on success, 1 on failure.
 *
 * KAT: SHA-256("abc") == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 */
#include <stdint.h>
#include <string.h>

/* ---- compact self-contained SHA-256 (all static, no external symbols) ---- */
#define _ST_ROR32(x,n) (((uint32_t)(x)>>(n))|((uint32_t)(x)<<(32-(n))))
#define _ST_CH(e,f,g)  (((e)&(f))^(~(e)&(g)))
#define _ST_MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define _ST_EP0(a)     (_ST_ROR32(a,2)^_ST_ROR32(a,13)^_ST_ROR32(a,22))
#define _ST_EP1(e)     (_ST_ROR32(e,6)^_ST_ROR32(e,11)^_ST_ROR32(e,25))
#define _ST_SIG0(x)    (_ST_ROR32(x,7)^_ST_ROR32(x,18)^((uint32_t)(x)>>3))
#define _ST_SIG1(x)    (_ST_ROR32(x,17)^_ST_ROR32(x,19)^((uint32_t)(x)>>10))

static const uint32_t _st_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
    0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
    0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
    0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
    0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
    0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void _st_sha256_block(uint32_t s[8], const uint8_t blk[64]) {
    uint32_t w[64]; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)
              |((uint32_t)blk[i*4+2]<<8)|(uint32_t)blk[i*4+3];
    for (i = 16; i < 64; i++)
        w[i] = _ST_SIG1(w[i-2]) + w[i-7] + _ST_SIG0(w[i-15]) + w[i-16];
    uint32_t a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for (i = 0; i < 64; i++) {
        uint32_t t1 = h + _ST_EP1(e) + _ST_CH(e,f,g) + _st_K[i] + w[i];
        uint32_t t2 = _ST_EP0(a) + _ST_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d;
    s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

static void _st_sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t s[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    uint8_t buf[64];
    size_t i, rem = len & 63u;
    for (i = 0; i + 64 <= len; i += 64)
        _st_sha256_block(s, msg + i);
    memcpy(buf, msg + i, rem);
    buf[rem] = 0x80;
    if (rem >= 56) {
        memset(buf + rem + 1, 0, 63 - rem);
        _st_sha256_block(s, buf);
        memset(buf, 0, 56);
    } else {
        memset(buf + rem + 1, 0, 55 - rem);
    }
    uint64_t bits = (uint64_t)len << 3;
    for (i = 0; i < 8; i++) buf[56 + i] = (uint8_t)(bits >> (56 - 8*i));
    _st_sha256_block(s, buf);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(s[i] >> 24);
        out[i*4+1] = (uint8_t)(s[i] >> 16);
        out[i*4+2] = (uint8_t)(s[i] >>  8);
        out[i*4+3] = (uint8_t) s[i];
    }
}

/* ---- KAT ---- */
static const uint8_t _st_abc_digest[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

int nextssl_wasm_selftest(void) {
    uint8_t digest[32];
    _st_sha256((const uint8_t *)"abc", 3, digest);
    return memcmp(digest, _st_abc_digest, 32) == 0 ? 0 : 1;
}
