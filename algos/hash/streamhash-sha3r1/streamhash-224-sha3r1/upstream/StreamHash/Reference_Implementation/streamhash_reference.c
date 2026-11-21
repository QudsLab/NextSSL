/* streamhash_reference.c by Michal Trojnara 2007-2008 */

#include "streamhash_reference.h"
#include "sbox32.h"

HashReturn Init(hashState *state, int hashbitlen) {
    int i;

    switch(hashbitlen) {
        case 224: case 256: case 384: case 512: break;
        default: return BAD_HASHLEN;
    }
    state->hashbitlen=hashbitlen;
    state->tablen=hashbitlen/32;
    for(i=0; i<state->tablen; ++i)
        state->tabval[i]=0; /* initial state value */
    state->bitval=state->bitlen=0;
    return SUCCESS;
}

HashReturn Update(hashState *state, const BitSequence *data,
        DataLength databitlen) {
    DataLength p, divlen=databitlen/8;
    BitSequence modlen=databitlen%8;
    int b, i;

    /* "all calls to  update will contain data lengths that
       are divisible by 8, except, possibly, the last call" */
    if(state->bitlen) /* it was previously changed to a non-zero value */
        return FAIL;

    /* the main loop */
    for(p=0; p<divlen; ++p) { /* each input byte */
        b=data[p];
        for(i=0; i<state->tablen; ++i) /* state vector */
            state->tabval[i]^=sbox32[(state->tabval[i]^b^i)&0xff];
    }

    /* save the remaining bits if any */
    if(modlen) { /* data length is not divisible by 8 (last call) */
        state->bitval=(BitSequence)(data[p] & 0xff<<(8-modlen));
        state->bitlen=modlen;
    }
    return SUCCESS;
}

HashReturn Final(hashState *state, BitSequence *hashval) {
    int i;

    /* update the state vector with the remaining input bits */
    hashval[0]=state->bitval;
    hashval[1]=state->bitlen;
    state->bitlen=0; /* reset the number of remaining bits */
    Update(state, hashval, 16); /* two bytes */

    /* update with least significant bytes of the state vector */
    for(i=0; i<state->tablen; ++i) {
        hashval[2*i+1]=(BitSequence)(state->tabval[i]>>8);
        hashval[2*i]=(BitSequence)(state->tabval[i]); /* LSB */
    }
    Update(state, hashval, 16*state->tablen);

    /* diffuse the state vector  */
    for(i=0; i<3*state->tablen; ++i) /* 3 interations per 32-bit word */
        state->tabval[(i+1)%state->tablen]+=state->tabval[i%state->tablen];

    /* copy the state vector using high-endian byte order */
    for(i=0; i<state->tablen; ++i) {
        hashval[4*i]=(BitSequence)(state->tabval[i]>>24); /* MSB */
        hashval[4*i+1]=(BitSequence)(state->tabval[i]>>16);
        hashval[4*i+2]=(BitSequence)(state->tabval[i]>>8);
        hashval[4*i+3]=(BitSequence)(state->tabval[i]); /* LSB */
    }

    /* diffuse the returned vector */
    for(i=0; i<4*state->tablen; ++i) /* 1 iteration per octet */
        hashval[(i+1)%(4*state->tablen)]+=hashval[i];

    return SUCCESS;
}

HashReturn Hash(int hashbitlen, const BitSequence *data,
        DataLength databitlen, BitSequence *hashval) {
    hashState state;

    return (HashReturn)((int)Init(&state, hashbitlen) ||
        (int)Update(&state, data, databitlen) ||
        (int)Final(&state, hashval));
}

/* end of streamhash_reference.c */
