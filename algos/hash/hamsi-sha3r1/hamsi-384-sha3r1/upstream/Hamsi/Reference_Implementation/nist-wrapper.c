#include <string.h>
#include <stdlib.h>
#include "words.h"
#include "nist.h"
#include "hamsi.h"
#include "hamsi-tables.h"

HashReturn Init(hashState *state,int hashbitlen) {
    int size=(hashbitlen<=256)?1:2;
    state->leftbits    = 0;
    state->counter     = 0;
    state->hashbitlen  = hashbitlen;
    state->ROUNDS      = 3*size;
    state->PFROUNDS    = 6*size;
    state->cvsize      = 256*size;

    if (hashbitlen==224)      { memcpy(state->state,iv224,32); }
    else if (hashbitlen==256) { memcpy(state->state,iv256,32); }
    else if (hashbitlen==384) { memcpy(state->state,iv384,64); }
    else if (hashbitlen==512) { memcpy(state->state,iv512,64); }
    else return BAD_HASHBITLEN;

    memset(state->leftdata,'\0',8);

    return SUCCESS;
}

HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen) {
    HashReturn ret=SUCCESS;
    int bits2hash=databitlen;
    int i;
    const BitSequence* block=data;
    const int s_blocksize=(state->cvsize/8);
    // Do first imcomplete block
    if (state->leftbits) {
        if ((state->leftbits+bits2hash) < s_blocksize) {
            // just copy, update leftbits
            for (i=0; i<((bits2hash+7)/8); ++i) state->leftdata[(state->leftbits/8)+i]=block[i];
            if (bits2hash%8) state->leftdata[(state->leftbits+bits2hash)/8] &= (0xff << (8-(bits2hash%8)));
            state->leftbits += bits2hash;
        } else {
            // copy and do first block from leftdata
            block += (s_blocksize - state->leftbits)/8;
            bits2hash -= (s_blocksize - state->leftbits);
            if (state->cvsize==256) {
                hash256(state->ROUNDS,state->state,state->leftdata,0);
            } else if (state->cvsize==512) {
                hash512(state->ROUNDS,state->state,state->leftdata,0);
            }
            state->leftbits=0;
        }
    }

    // do all complete blocks
    for (; bits2hash >= s_blocksize; bits2hash-=s_blocksize) {
        if (state->cvsize==256) {
            hash256(state->ROUNDS,state->state,block,0);
        } else if (state->cvsize==512) {
            hash512(state->ROUNDS,state->state,block,0);
        }
        block += (s_blocksize/8);
        ++(state->counter);
    }

    // copy leftover data, update leftbits
    state->leftbits = bits2hash;
    for (i=0; i<((bits2hash+7)/8); ++i) state->leftdata[i]=block[i];

    return ret;
}
 
inline void HV(BitSequence *h,int i,Word w) {
    h[4*(i)]=((w)>>24)&0xff;
    h[4*(i)+1]=((w)>>16)&0xff;
  
    h[4*(i)+2]=((w)>>8)&0xff;
    h[4*(i)+3]=w&0xff;
}

HashReturn Final(hashState* state, BitSequence *hashval) {
  const int block_bytes=(state->cvsize/8)/8;
  int i;
  U64 length = ((U64)(state->cvsize)*state->counter)+state->leftbits;
  BitSequence lenbytes[8];

  HashReturn ret=SUCCESS;

  // Padding
  state->leftdata[state->leftbits/8] &= (0xff<<(8-(state->leftbits%8)));
  state->leftdata[state->leftbits/8] |= (1<<(7-(state->leftbits%8)));
  for (i=(state->leftbits/8)+1; i<block_bytes; ++i) state->leftdata[i]=0;

  // position data length in lenbytes, BIG endian
  for (i=0; i<8; ++i) lenbytes[i] = (length>>(8*(7-i)))&0xff;

  // Processing padding and length
  if (state->cvsize==256) {
      hash256(state->ROUNDS,state->state,state->leftdata,0);
      hash256(state->ROUNDS,state->state,lenbytes,0);
      hash256(state->PFROUNDS,state->state,lenbytes+4,1);
  } else if (state->cvsize==512) {
      hash512(state->ROUNDS,state->state,state->leftdata,0);
      hash512(state->PFROUNDS,state->state,lenbytes,1);
  }

  // Truncation
  if (state->hashbitlen==384) {
      int T_384[12] = { 0, 1, 3, 4, 5, 6, 8, 9, 10, 12, 13, 15 };
      for (i=0; i<12; ++i) HV(hashval,i,state->state[T_384[i]]);
          // hashval[i] = state->state[T_384[i]];
  } else
      //memcpy(hashval,state->state,state->hashbitlen/8);
      for (i=0; i<(state->hashbitlen/32); ++i)
          HV(hashval,i,state->state[i]);
          // hashval[i] = state->state[i];

  return ret;
}

HashReturn Hash(int hashbitlen, const BitSequence* data, DataLength databitlen, BitSequence *hashval) {
    static hashState MyState;
    HashReturn ret;
    ret = Init(&MyState,hashbitlen);
    if (ret) return ret;
    ret = Update(&MyState,data,databitlen);
    if (ret) return ret;
    else return Final(&MyState,hashval);
}
