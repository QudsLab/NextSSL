/*******************************/
/* luffa.c                     */
/* Version 2.0 (Sep 15th 2009) */
/* Made by Hitachi Ltd.        */
/*******************************/

#include <string.h>
#include "luffa.h"


#ifdef HASH_BIG_ENDIAN
# define BYTES_SWAP32(x) x
# define BYTES_SWAP64(x) x
#else
# define BYTES_SWAP32(x)                                                \
    ((x << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | (x >> 24))

# define BYTES_SWAP64(x)                                                \
    (((u64)(BYTES_SWAP32((u32)(x))) << 32) | (u64)(BYTES_SWAP32((u32)((x) >> 32))))
#endif /* HASH_BIG_ENDIAN */

/* BYTES_SWAP256(x) stores each 32-bit word of 256 bits data in little-endian convention */
#define BYTES_SWAP256(x) {                                      \
    int _i = 8; while(_i--){x[_i] = BYTES_SWAP32(x[_i]);}   \
    }

/* BYTES_SWAP512(x) stores each 64-bit word of 512 bits data in little-endian convention */
#define BYTES_SWAP512(x) {                                      \
    int _i = 8; while(_i--){x[_i] = BYTES_SWAP64(x[_i]);}   \
    }


void rnd(hashState *state, uint32 *c);
void tweak(hashState *state);
void mi(hashState *state);
void step(hashState *state, uint32 *c);
void step_part(uint32 *a, uint32 *c);
void subcrumb(uint32 *a0, uint32 *a1, uint32 *a2, uint32 *a3);
void mixword(uint32 *a);
void addconstant(uint32 *a, uint32 *cns);
void genconstant(uint32 *c, uint32 *cns);
void finalization(hashState *state, uint32 *b);
void process_last_msgs(hashState *state);

/* initial values of constant generators */
const uint32 CNS[10] = {
    0x181cca53,0x380cde06,
    0x5b6f0876,0xf16f8594,
    0x7e106ce9,0x38979cb0,
    0xbb62f364,0x92e93c29,
    0x9a025047,0xcff2a940
};

/* initial values of chaining variables */
const uint32 IV[40] = {
    0x6d251e69,0x44b051e0,0x4eaa6fb4,0xdbf78465,
    0x6e292011,0x90152df4,0xee058139,0xdef610bb,
    0xc3b44b95,0xd9d2f256,0x70eee9a0,0xde099fa3,
    0x5d9b0557,0x8fc944b3,0xcf1ccf0e,0x746cd581,
    0xf7efc89d,0x5dba5781,0x04016ce5,0xad659c05,
    0x0306194f,0x666d1836,0x24aa230a,0x8b264ae7,
    0x858075d5,0x36d79cce,0xe571f7d7,0x204b1f67,
    0x35870c6a,0x57e9e923,0x14bcb808,0x7cde72ce,
    0x6c68e9be,0x5ec41e22,0xc825b7c7,0xaffb4363,
    0xf5df3999,0x0fc688f1,0xb07224cc,0x03e86cea
};


HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval) 
{
    hashState state;
    HashReturn ret;

    ret = Init(&state, hashbitlen);
    if(ret != SUCCESS) {
        return ret;
    }

    ret = Update(&state, data, databitlen);
    if(ret != SUCCESS) {
        return ret;
    }

    ret = Final(&state, hashval);
    if(ret != SUCCESS) {
        return ret;
    }
    return SUCCESS;
}


HashReturn Init(hashState *state, int hashbitlen)
{
    state->hashbitlen = hashbitlen;

    switch(hashbitlen) {

    case 224:
        memset(state->bitlen, 0, LIMIT_224/8);
        state->width = WIDTH_224;
        memcpy(state->chainv, IV, WIDTH_224*32);
        break;

    case 256:
        memset(state->bitlen, 0, LIMIT_256/8);
        state->width = WIDTH_256;
        memcpy(state->chainv, IV, WIDTH_256*32);
        break;

    case 384:
        memset(state->bitlen, 0, LIMIT_384/8);
        state->width = WIDTH_384;
        memcpy(state->chainv, IV, WIDTH_384*32);
        break;

    case 512:
        memset(state->bitlen, 0, LIMIT_512/8);
        state->width = WIDTH_512;
        memcpy(state->chainv, IV, WIDTH_512*32);
        break;

    default:
        return BAD_HASHBITLEN;
    }

    state->rembitlen = 0;

    memset(state->buffer, 0, MSG_BLOCK_BYTE_LEN);

    return SUCCESS;
}


HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
    HashReturn ret;
    int i;
    uint8 *p = (uint8*)state->buffer;
    uint32 cpylen;
    uint32 len;
    uint32 c[10];

    switch(state->hashbitlen) {

    case 224:
    case 256:
    case 384:
    case 512:
        if(state->hashbitlen==224||state->hashbitlen==256)
            state->bitlen[0] += databitlen;
        else {
            if((state->bitlen[1] += databitlen) < databitlen) {
                state->bitlen[0] +=1;
            }
        }

        if(state->rembitlen + databitlen >= MSG_BLOCK_BIT_LEN) {
            cpylen = MSG_BLOCK_BYTE_LEN - (state->rembitlen >> 3);

            memcpy(p + (state->rembitlen >> 3), data, cpylen);

            BYTES_SWAP256(state->buffer);

            for(i=0;i<(state->width*2);i++) c[i] = CNS[i];
            rnd(state, c);

            databitlen -= (cpylen << 3);
            data += cpylen;
            state->rembitlen = 0;

            while (databitlen >= MSG_BLOCK_BIT_LEN) {
                memcpy(p, data, MSG_BLOCK_BYTE_LEN);

                BYTES_SWAP256(state->buffer);

                for(i=0;i<(state->width*2);i++) c[i] = CNS[i];
                rnd(state, c);

                databitlen -= MSG_BLOCK_BIT_LEN;
                data += MSG_BLOCK_BYTE_LEN;
            }
        }

        /* All remaining data copy to buffer */
        if(databitlen) {
            len = databitlen >> 3;
            if(databitlen % 8 != 0) {
                len += 1;
            }

            memcpy(p + (state->rembitlen >> 3), data, len);
            state->rembitlen += databitlen;
        }

        ret = SUCCESS;
        break;

    default:
        ret = BAD_HASHBITLEN;
        break;
    }

    return ret;
}


HashReturn Final(hashState *state, BitSequence *hashval) 
{
    HashReturn ret;

    switch(state->hashbitlen) {

    case 224:
    case 256:
    case 384:
    case 512:
        process_last_msgs(state);
        finalization(state, (uint32*) hashval);
        ret = SUCCESS;
        break;

    default:
        ret = BAD_HASHBITLEN;
        break;
    }

    return ret;
}


/***************************************************/
/* Round function         */
/* state: hash context    */
/* c[10]: constant        */
void rnd(hashState *state, uint32 *c)
{
    int i;
  
    mi(state);

    tweak(state);

    for(i=0;i<8;i++) {
        step(state, c);
    }
  
    return;
}


/***************************************************/
/* Tweaks */
void tweak(hashState *state) {
    int i,j;

    for(j=0;j<state->width;j++) {
        for(i=4;i<8;i++) {
            state->chainv[8*j+i] = (state->chainv[8*j+i]<<j) | (state->chainv[8*j+i]>>(32-j));
        }
    }

    return;
}


/***************************************************/
/* Multiplication by 2 on GF(2^8)^32 */
/* a[8]: chaining value              */
void mult2(uint32 a[8])
{
    uint32 tmp;

    tmp = a[7];
    a[7] = a[6];
    a[6] = a[5];
    a[5] = a[4];
    a[4] = a[3] ^ tmp;
    a[3] = a[2] ^ tmp;
    a[2] = a[1];
    a[1] = a[0] ^ tmp;
    a[0] = tmp;

    return;
}


/***************************************************/
/* Message Insertion function */
/* state: hash context        */
void mi(hashState *state)
{
    uint32 t[40];
    int i, j;

/* mixing layer w=3,4,5 */
    for(i=0;i<8;i++) {
        t[i]=0;
        for(j=0;j<state->width;j++) {
            t[i] ^= state->chainv[i+8*j];
        }
    }
    mult2(t);

    for(j=0;j<state->width;j++) {
        for(i=0;i<8;i++) {
            state->chainv[i+8*j] ^= t[i];
        }
    }

/* mixing layer w=5 */
    if(state->width>=5) {
        for(j=0;j<state->width;j++) {
            for(i=0;i<8;i++) t[i+8*j] = state->chainv[i+8*j];
            mult2(&state->chainv[8*j]);
        }
        for(j=0;j<state->width;j++) {
            for(i=0;i<8;i++) state->chainv[8*j+i] ^= t[8*((j+1)%state->width)+i];
        }
    }

/* mixing layer w=4,5 */
    if(state->width>=4) {
        for(j=0;j<state->width;j++) {
            for(i=0;i<8;i++) t[i+8*j] = state->chainv[i+8*j];
            mult2(&state->chainv[8*j]);
        }
        for(j=0;j<state->width;j++) {
            for(i=0;i<8;i++) state->chainv[8*j+i] ^= t[8*((j-1+state->width)%state->width)+i];
        }
    }

/* message addtion */
    for(j=0;j<state->width;j++) {
        for(i=0;i<8;i++) {
            state->chainv[i+8*j] ^= state->buffer[i];
        }

        mult2(state->buffer);
    }
  
    return;
}


/***************************************************/
/* Step function          */
/* state: hash context    */
/* c[10]: constant        */
void step(hashState *state, uint32 *c)
{
    int j;

    for(j=0;j<state->width;j++) {
        step_part(state->chainv + 8*j, c+2*j);
    }

    return;
}


/***************************************************/
/* Step function of a Sub-Permutation              */
/* a[8]: chaining values of a Sub-Permutation line */
/* c[2]: constant of a Sub-Permutation line        */
void step_part(uint32 *a, uint32 *c)
{
    uint32 cns[2];
  
    subcrumb(a  , a+1, a+2, a+3);
    subcrumb(a+5, a+6, a+7, a+4);
    mixword(a  );
    mixword(a+1);
    mixword(a+2);
    mixword(a+3);
    genconstant(c, cns);
    addconstant(a, cns);
  
    return;
}


/***************************************************/
/* SubCrumb function                              */
/* a[4]: input and output of SubCrumb             */
/* (a[0],a[1],a[2],a[3]) -> (a[0],a[1],a[2],a[3]) */
void subcrumb(uint32 *a0, uint32 *a1, uint32 *a2, uint32 *a3)
{
    uint32 tmp;
  
    tmp  = *a0;
    *a0 |= *a1;
    *a2 ^= *a3;
    *a1  = ~*a1;
    *a0 ^= *a3;
    *a3 &= tmp;
    *a1 ^= *a3;
    *a3 ^= *a2;
    *a2 &= *a0;
    *a0  = ~*a0;
    *a2 ^= *a1;
    *a1 |= *a3;
    tmp ^= *a1;
    *a3 ^= *a2;
    *a2 &= *a1;
    *a1 ^= *a0;
    *a0  = tmp;
  
    return;
}


/***************************************************/
/* MixWord function                                 */
/* a[0],a[4]: input and outputs of MixWord function */
/* (a[0],a[4]) -> (a[0],a[4])                       */
void mixword(uint32 *a)
{
    a[4] ^= a[0];
    a[0]  = (a[0]<< 2) | (a[0]>>(32-2));
    a[0] ^= a[4];
    a[4]  = (a[4]<<14) | (a[4]>>(32-14));
    a[4] ^= a[0];
    a[0]  = (a[0]<<10) | (a[0]>>(32-10));
    a[0] ^= a[4];
    a[4]  = (a[4]<< 1) | (a[4]>>(32-1));

    return;
}


/***************************************************/
/* AddConstant function       */
/* a[0],a[4]: chaining values */
/* cns[2]: round constants    */
void addconstant(uint32 *a, uint32 *cns)
{
    a[0] ^= cns[0];
    a[4] ^= cns[1];
  
    return;
}


/***************************************************/
/* Constant Generator */
/* This function generates
   round constants of a sub-permutation at a round. */
/* c[2]: the variables which LFSR possess at the round. */
/* cns[2]: the round constants at the round which are generated
   through two LFSR-round calculation. */
void genconstant(uint32 *c, uint32 *cns)
{
    if(c[0]>>31) {
        c[0] = (c[0]<<1) ^ (c[1]>>31) ^ 0xc4d6496c;
        c[1] = (c[1]<<1) ^ 0x55c61c8d;
    } else {
        c[0] = (c[0]<<1) ^ (c[1]>>31);
        c[1] <<= 1;
    }
    cns[0] = c[0];
    c[0] = c[1];
    c[1] = cns[0];
    if(c[0]>>31) {
        c[0] = (c[0]<<1) ^ (c[1]>>31) ^ 0xc4d6496c;
        c[1] = (c[1]<<1) ^ 0x55c61c8d;
    } else {
        c[0] = (c[0]<<1) ^ (c[1]>>31);
        c[1] <<= 1;
    }
    cns[1] = c[0];
    c[0] = c[1];
    c[1] = cns[1];
  
    return;
}


/***************************************************/
/* Finalization function  */
/* state: hash context    */
/* b[8]: hash values      */
void finalization(hashState *state, uint32 *b)
{
    int i,j;
    uint32 c[10];

    /*---- blank round with m=0 ----*/
    memset(state->buffer, 0, MSG_BLOCK_BYTE_LEN);
    memcpy(c, CNS, state->width*8);
    rnd(state, c);

    switch(state->hashbitlen) {
    case 224:
        for(i=0;i<7;i++) {
            b[i] = 0;
            for(j=0;j<state->width;j++) {
                b[i] ^= state->chainv[i+8*j];
            }
            b[i] = BYTES_SWAP32((b[i]));
        }
        break;

    case 256:
    case 384:
    case 512:
        for(i=0;i<8;i++) {
            b[i] = 0;
            for(j=0;j<state->width;j++) {
                b[i] ^= state->chainv[i+8*j];
            }
            b[i] = BYTES_SWAP32((b[i]));
        }
        if(state->hashbitlen == 256) break;

        memset(state->buffer, 0, MSG_BLOCK_BYTE_LEN);
        memcpy(c, CNS, state->width*8);
        rnd(state, c);

        for(i=0;i<4;i++) {
            b[8+i] = 0;
            for(j=0;j<state->width;j++) {
                b[8+i] ^= state->chainv[i+8*j];
            }
            b[8+i] = BYTES_SWAP32((b[8+i]));
        }
        if(state->hashbitlen == 384) break;

        for(i=4;i<8;i++) {
            b[8+i] = 0;
            for(j=0;j<state->width;j++) {
                b[8+i] ^= state->chainv[i+8*j];
            }
            b[8+i] = BYTES_SWAP32((b[8+i]));
        }
        break;
    default:
        break;
    }

    return;
}


/***************************************************/
/* Process of the last blocks */
/* state: hash context        */
void process_last_msgs(hashState *state)
{
    int i=0;
    uint32 tail_len;
    uint32 c[10];
  
    if(state->hashbitlen == 224||state->hashbitlen==256)
        tail_len = ((uint32) state->bitlen[0])%MSG_BLOCK_BIT_LEN;
    else
        tail_len = ((uint32) state->bitlen[1])%MSG_BLOCK_BIT_LEN;

    i= tail_len/8;

    if(!(tail_len%8)) {
        ((uint8*)state->buffer)[i] = 0x80;
    }
    else {
        ((uint8*)state->buffer)[i] &= (0xff<<(8-(tail_len%8)));
        ((uint8*)state->buffer)[i] |= (0x80>>(tail_len%8));
    }

    i++;

    for(;i<32;i++)
        ((uint8*)state->buffer)[i] = 0;
  
    for(i=0;i<8;i++) {
        state->buffer[i] = BYTES_SWAP32((state->buffer[i]));
    }
    for(i=0;i<state->width*2;i++) c[i] = CNS[i];
    rnd(state, c);

    return;
}

/***************************************************/
